require('dotenv').config();
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { exec } = require('child_process');
const { Worker } = require('worker_threads');
const AdmZip = require('adm-zip');
const plist = require('plist');
const bplistParser = require('bplist-parser');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

const {
  PORT = 4500,
  UPLOAD_URL = 'https://yoursite.com/',
  DEFAULT_IPA_PATH = './Portal-1.9.0.ipa',
  ENCRYPTION_KEY,
  RATE_LIMIT_WINDOW_MS = 900000,
  RATE_LIMIT_MAX = 100,
  LOG_LEVEL = 'info',
} = process.env;

if (!ENCRYPTION_KEY || Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error('Error: ENCRYPTION_KEY must be set in .env and be 64 hex chars (32 bytes).');
  process.exit(1);
}

let defaultIpaAvailable = false;
if (fs.existsSync(DEFAULT_IPA_PATH)) {
  defaultIpaAvailable = true;
  console.log(`Default IPA found at: ${DEFAULT_IPA_PATH}`);
} else {
  console.warn(`Warning: Default IPA not found at path: ${DEFAULT_IPA_PATH}. It will not be used if no IPA is uploaded.`);
}

const WORK_DIR = path.join(__dirname, 'uploads');
const REQUIRED_DIRS = ['p12', 'mp', 'temp', 'signed', 'plist'];

const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir);
}

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
    }),
  ],
});

logger.add(
  new winston.transports.Console({
    format: winston.format.simple(),
  })
);

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: parseInt(RATE_LIMIT_WINDOW_MS, 10),
  max: parseInt(RATE_LIMIT_MAX, 10),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

for (const dir of REQUIRED_DIRS) {
  const dirPath = path.join(WORK_DIR, dir);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    logger.info(`Created directory: ${dirPath}`);
  }
}

app.use(express.static(path.join(__dirname, 'public')));
app.use('/signed', express.static(path.join(WORK_DIR, 'signed')));
app.use('/plist', express.static(path.join(WORK_DIR, 'plist')));

const upload = multer({
  dest: path.join(WORK_DIR, 'temp'),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.ipa', '.p12', '.mobileprovision'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only .ipa, .p12, and .mobileprovision are allowed.'));
    }
  },
});

function generateRandomSuffix() {
  const randomStr = Math.random().toString(36).substring(2, 8);
  return `${Date.now()}_${randomStr}`;
}

function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '');
}

const algorithm = 'aes-256-cbc';
const key = Buffer.from(ENCRYPTION_KEY, 'hex');
const ivLength = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

function decrypt(encryptedText) {
  const [ivStr, encrypted] = encryptedText.split(':');
  if (!ivStr || !encrypted) throw new Error('Invalid encrypted text format');
  const iv = Buffer.from(ivStr, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function generateManifestPlist(ipaUrl, bundleId, bundleVersion, displayName) {
  const defaultBundleId = 'com.example.default';
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>items</key>
    <array>
      <dict>
        <key>assets</key>
        <array>
          <dict>
            <key>kind</key>
            <string>software-package</string>
            <key>url</key>
            <string>${ipaUrl}</string>
          </dict>
          <dict>
            <key>kind</key>
            <string>display-image</string>
            <key>needs-shine</key>
            <false/>
            <key>url</key>
            <string>https://raw.githubusercontent.com/daisuke1227/RevengeUpdates/refs/heads/main/IMG_0651.png</string>
          </dict>
          <dict>
            <key>kind</key>
            <string>full-size-image</string>
            <key>needs-shine</key>
            <false/>
            <key>url</key>
            <string>https://raw.githubusercontent.com/daisuke1227/RevengeUpdates/refs/heads/main/IMG_0651.png</string>
          </dict>
        </array>
        <key>metadata</key>
        <dict>
          <key>bundle-identifier</key>
          <string>${bundleId || defaultBundleId}</string>
          <key>bundle-version</key>
          <string>${bundleVersion}</string>
          <key>kind</key>
          <string>software</string>
          <key>title</key>
          <string>${displayName}</string>
        </dict>
      </dict>
    </array>
  </dict>
</plist>`;
}

function execPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        logger.error(`Command failed: ${cmd}`);
        logger.error(`stderr: ${stderr}`);
        return reject(new Error(stderr || error.message));
      }
      logger.info(`Command output: ${stdout}`);
      resolve(stdout.trim());
    });
  });
}

async function checkCertificateValidity(p12Path, password = '') {
  const pemPath = p12Path.replace('.p12', '.pem');
  try {
    const cmdConvert = password
      ? `openssl pkcs12 -in "${p12Path}" -out "${pemPath}" -nodes -passin pass:${password}`
      : `openssl pkcs12 -in "${p12Path}" -out "${pemPath}" -nodes -passin pass:`;
    await execPromise(cmdConvert);
    const cmdCheck = `openssl x509 -in "${pemPath}" -noout -dates`;
    const checkOutput = await execPromise(cmdCheck);
    logger.info(`Certificate dates:\n${checkOutput}`);
  } catch (err) {
    throw new Error('Invalid or expired certificate, or wrong password.');
  } finally {
    if (fs.existsSync(pemPath)) {
      await fsp.unlink(pemPath);
    }
  }
}

function signIpaInWorker({ p12Path, p12Password, mpPath, ipaPath, signedIpaPath }) {
  return new Promise((resolve, reject) => {
    const workerData = { p12Path, p12Password, mpPath, ipaPath, signedIpaPath };
    const worker = new Worker(path.join(__dirname, 'zsign-worker.js'), {
      workerData,
    });

    worker.on('message', (message) => {
      if (message.status === 'ok') {
        resolve(message);
      } else {
        reject(new Error(message.error));
      }
    });

    worker.on('error', (err) => {
      reject(err);
    });

    worker.on('exit', (code) => {
      if (code !== 0) {
        reject(new Error(`Worker stopped with exit code ${code}`));
      }
    });
  });
}

app.post(
  '/sign',
  upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'mobileprovision', maxCount: 1 },
  ]),
  async (req, res) => {
    logger.info('Sign Request Received');
    let uniqueSuffix;
    let ipaPath;
    let p12Path;
    let mpPath;
    let signedIpaPath;

    try {
      if (!req.files?.p12 || !req.files?.mobileprovision) {
        return res.status(400).json({
          error: 'P12 and MobileProvision files are required.',
        });
      }

      if (req.files.ipa) {
        uniqueSuffix = generateRandomSuffix();
        ipaPath = path.join(WORK_DIR, 'temp', `input_${uniqueSuffix}.ipa`);
        await fsp.rename(req.files.ipa[0].path, ipaPath);
        logger.info(`Received IPA: ${req.files.ipa[0].originalname}`);
      } else {
        if (defaultIpaAvailable) {
          ipaPath = DEFAULT_IPA_PATH;
          logger.info(`No IPA uploaded. Using default IPA: ${ipaPath}`);
        } else {
          return res.status(400).json({
            error: 'No IPA was uploaded, and no default IPA is available on the server.',
          });
        }
      }

      const p12Password = (req.body.p12_password || '').trim();
      const saveCert = req.body.save_cert === 'on';

      if (!uniqueSuffix) uniqueSuffix = generateRandomSuffix();
      p12Path = path.join(WORK_DIR, 'p12', `cert_${uniqueSuffix}.p12`);
      mpPath = path.join(WORK_DIR, 'mp', `app_${uniqueSuffix}.mobileprovision`);

      await fsp.rename(req.files.p12[0].path, p12Path);
      await fsp.rename(req.files.mobileprovision[0].path, mpPath);

      logger.info(
        saveCert
          ? `Saved certs permanently: p12 -> ${p12Path}, mp -> ${mpPath}`
          : `Using temporary certs: p12 -> ${p12Path}, mp -> ${mpPath}`
      );

      try {
        if (p12Password) {
          await checkCertificateValidity(p12Path, p12Password);
        } else {
          await checkCertificateValidity(p12Path, '');
        }
      } catch (certErr) {
        return res.status(400).json({
          error: certErr.message || 'Invalid certificate or password.',
        });
      }

      if (saveCert && p12Password) {
        const encryptedPwd = encrypt(p12Password);
        const pwdPath = path.join(WORK_DIR, 'p12', `password_${uniqueSuffix}.enc`);
        await fsp.writeFile(pwdPath, encryptedPwd, 'utf8');
        logger.info(`Saved encrypted password at: ${pwdPath}`);
      }

      signedIpaPath = path.join(WORK_DIR, 'signed', `signed_${uniqueSuffix}.ipa`);

      try {
        await signIpaInWorker({
          p12Path,
          p12Password,
          mpPath,
          ipaPath,
          signedIpaPath,
        });
      } catch (zsignErr) {
        const errorMsg = zsignErr.message.toLowerCase();
        if (
          errorMsg.includes('pkcs12') ||
          errorMsg.includes('password') ||
          errorMsg.includes('mac verify error')
        ) {
          return res.status(400).json({
            error: 'Wrong P12 password or invalid certificate. Check your .p12.',
          });
        }
        if (errorMsg.includes('ipa') || errorMsg.includes('error parsing')) {
          return res.status(400).json({
            error: 'Failed to sign. The IPA might be corrupted or invalid.',
          });
        }
        logger.error(`zsign failed: ${zsignErr}`);
        return res.status(500).json({
          error: 'Signing process failed. Check server logs.',
          details: zsignErr.message,
        });
      }

      logger.info(`Signed IPA successfully created at: ${signedIpaPath}`);

      const zipSigned = new AdmZip(signedIpaPath);
      const zipEntries = zipSigned.getEntries();
      let appFolderName = '';
      for (const entry of zipEntries) {
        const parts = entry.entryName.split('/');
        if (parts.length > 1 && parts[1].endsWith('.app')) {
          appFolderName = parts[1];
          break;
        }
      }
      if (!appFolderName) {
        return res.status(500).json({
          error: "Couldn't find .app directory in the signed IPA.",
        });
      }

      const plistEntryPath = `Payload/${appFolderName}/Info.plist`;
      const plistEntry = zipSigned.getEntry(plistEntryPath);
      if (!plistEntry) {
        return res.status(500).json({
          error: 'Info.plist not found in the signed IPA.',
        });
      }

      let plistData;
      const plistBuffer = plistEntry.getData();
      try {
        plistData = plist.parse(plistBuffer.toString('utf8'));
      } catch (xmlErr) {
        try {
          const parsed = await bplistParser.parseBuffer(plistBuffer);
          if (parsed && parsed.length > 0) plistData = parsed[0];
          else throw new Error('Parsed binary plist is empty.');
        } catch (binErr) {
          logger.error('Both XML and binary plist parsing failed.');
          return res.status(500).json({ error: 'Failed to parse Info.plist from signed IPA.' });
        }
      }

      const bundleId = plistData.CFBundleIdentifier || 'com.example.unknown';
      const bundleVersion = plistData.CFBundleVersion || '1.0.0';
      const displayName = plistData.CFBundleDisplayName || plistData.CFBundleName || 'App';

      const ipaUrl = new URL(`signed/${path.basename(signedIpaPath)}`, UPLOAD_URL).toString();
      const manifest = generateManifestPlist(ipaUrl, bundleId, bundleVersion, displayName);

      const filename = `${sanitizeFilename(displayName)}_${uniqueSuffix}.plist`;
      const plistSavePath = path.join(WORK_DIR, 'plist', filename);
      await fsp.writeFile(plistSavePath, manifest, 'utf8');

      const manifestUrl = new URL(`plist/${filename}`, UPLOAD_URL).toString();
      // Removed encodeURIComponent to eliminate encoding from the link
      const installLink = `itms-services://?action=download-manifest&url=${manifestUrl}`;

      return res.json({ installLink });
    } catch (err) {
      logger.error(`Error during signing process: ${err}`);
      return res.status(500).json({
        error: 'Unexpected error during signing. Check server logs.',
        details: err.message,
      });
    } finally {
      try {
        if (uniqueSuffix) {
          if (req.files?.ipa && ipaPath !== DEFAULT_IPA_PATH && fs.existsSync(ipaPath)) {
            await fsp.unlink(ipaPath);
            logger.info(`Removed uploaded IPA: ${ipaPath}`);
          }
          if (req.files?.p12 && req.files?.mobileprovision) {
            const notSaving = req.body.save_cert !== 'on';
            if (notSaving && fs.existsSync(p12Path)) {
              await fsp.unlink(p12Path);
              logger.info(`Removed temporary p12: ${p12Path}`);
            }
            if (notSaving && fs.existsSync(mpPath)) {
              await fsp.unlink(mpPath);
              logger.info(`Removed temporary mobileprovision: ${mpPath}`);
            }
          }
        }
      } catch (cleanupErr) {
        logger.error(`Error during cleanup: ${cleanupErr}`);
      }
    }
  }
);

function multerErrorHandler(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum allowed size is 2GB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
  return next();
}
app.use(multerErrorHandler);

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}.`);
});
