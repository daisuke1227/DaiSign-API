const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { exec } = require('child_process');
const AdmZip = require('adm-zip');
const plist = require('plist');
const bplistParser = require('bplist-parser');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const UPLOAD_URL = 'https://yoursite.com/';
const WORK_DIR = path.join(__dirname, 'uploads');
const ENCRYPTION_KEY =
  '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const DEFAULT_IPA_PATH = path.join(__dirname, 'Portal-1.9.0.ipa');

if (!fs.existsSync(DEFAULT_IPA_PATH)) {
  console.error(`Error: Default IPA not found at path: ${DEFAULT_IPA_PATH}`);
  process.exit(1);
}

// Validate encryption key length
if (Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error('Error: ENCRYPTION_KEY must be 64 hex characters (32 bytes).');
  process.exit(1);
}

// Ensure necessary subdirectories exist
['p12', 'mp', 'temp', 'signed', 'plist'].forEach((dir) => {
  const dirPath = path.join(WORK_DIR, dir);
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
});

app.use('/signed', express.static(path.join(WORK_DIR, 'signed')));
app.use('/plist', express.static(path.join(WORK_DIR, 'plist')));

// -- Multer Configuration --
const upload = multer({
  dest: path.join(WORK_DIR, 'temp'),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.ipa', '.p12', '.mobileprovision'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          'Invalid file type. Only .ipa, .p12, and .mobileprovision are allowed.'
        )
      );
    }
  },
});

/**
 * Executes a shell command, returning a Promise.
 */
function execPromise(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.error(`Command failed: ${cmd}`);
        console.error(`stderr: ${stderr}`);
        return reject(new Error(stderr || error.message));
      }
      console.log(`Command output: ${stdout}`);
      resolve(stdout.trim());
    });
  });
}

/**
 * Generates a unique suffix (timestamp + random string).
 */
function generateRandomSuffix() {
  const randomStr = Math.random().toString(36).substring(2, 8);
  return `${Date.now()}_${randomStr}`;
}

/**
 * Sanitizes a display name to use in the .plist filename.
 */
function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '');
}

// -- Encryption/Decryption Helpers --
const algorithm = 'aes-256-cbc';
const key = Buffer.from(ENCRYPTION_KEY, 'hex'); // 32-byte key
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
  if (!ivStr || !encrypted) {
    throw new Error('Invalid encrypted text format');
  }
  const iv = Buffer.from(ivStr, 'hex');
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Generates the manifest plist content.
 */
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

// -- The /sign Route --
app.post(
  '/sign',
  upload.fields([
    { name: 'ipa', maxCount: 1 },
    { name: 'p12', maxCount: 1 },
    { name: 'mobileprovision', maxCount: 1 },
  ]),
  async (req, res) => {
    console.log('Sign Request Received');

    let uniqueSuffix;
    let ipaPath;
    let p12Path;
    let mpPath;
    let signedIpaPath;

    try {
      // 1. Check for missing files
      if (!req.files?.p12 || !req.files?.mobileprovision) {
        // Either p12 or mobileprovision is missing
        return res.status(400).json({
          error: 'P12 and MobileProvision files are required.',
        });
      }

      // 2. Handle the IPA input
      if (req.files?.ipa) {
        uniqueSuffix = generateRandomSuffix();
        ipaPath = path.join(WORK_DIR, 'temp', `input_${uniqueSuffix}.ipa`);
        await fsp.rename(req.files.ipa[0].path, ipaPath);
        console.log(`Received IPA: ${req.files.ipa[0].originalname}`);
      } else {
        ipaPath = DEFAULT_IPA_PATH; // Use default IPA if none uploaded
        console.log(`No IPA uploaded. Using default IPA at: ${DEFAULT_IPA_PATH}`);
      }

      // 3. Handle the P12 and MobileProvision
      const p12Password = req.body.p12_password?.trim();
      const saveCert = req.body.save_cert === 'on';

      // Generate a suffix if not already done
      if (!uniqueSuffix) uniqueSuffix = generateRandomSuffix();

      p12Path = path.join(WORK_DIR, 'p12', `cert_${uniqueSuffix}.p12`);
      mpPath = path.join(WORK_DIR, 'mp', `app_${uniqueSuffix}.mobileprovision`);

      // Move the uploaded files
      await fsp.rename(req.files.p12[0].path, p12Path);
      await fsp.rename(req.files.mobileprovision[0].path, mpPath);

      console.log(
        saveCert
          ? `Saved certificates permanently: p12 -> ${p12Path}, mp -> ${mpPath}`
          : `Using temporary certificates: p12 -> ${p12Path}, mp -> ${mpPath}`
      );

      // 3a. Encrypt p12 password if saving cert
      if (saveCert && p12Password) {
        const encryptedPassword = encrypt(p12Password);
        const passwordPath = path.join(
          WORK_DIR,
          'p12',
          `password_${uniqueSuffix}.enc`
        );
        await fsp.writeFile(passwordPath, encryptedPassword, 'utf8');
        console.log(`Saved encrypted password at: ${passwordPath}`);
      }

      // 4. zsign signing step
      signedIpaPath = path.join(WORK_DIR, 'signed', `signed_${uniqueSuffix}.ipa`);

      let zsignCmd = `zsign -c 5 -k "${p12Path}" `;
      if (p12Password) {
        zsignCmd += `-p "${p12Password}" `;
      }
      zsignCmd += `-m "${mpPath}" -o "${signedIpaPath}" "${ipaPath}"`;

      console.log(`Executing zsign command: ${zsignCmd}`);
      try {
        await execPromise(zsignCmd);
      } catch (err) {
        // Detect if it's likely a wrong password or corrupted IPA or something else
        const errorMsg = err.message.toLowerCase();

        if (
          errorMsg.includes('pkcs12') ||
          errorMsg.includes('password') ||
          errorMsg.includes('mac verify error')
        ) {
          return res.status(400).json({
            error: 'Wrong P12 password or invalid certificate. Please check your p12 file and password.',
          });
        }

        if (errorMsg.includes('ipa') || errorMsg.includes('error parsing')) {
          return res.status(400).json({
            error: 'Failed to sign IPA. The IPA might be corrupted or invalid.',
          });
        }

        // Fallback for any other errors
        return res.status(500).json({
          error: 'Signing process failed. Please check server logs.',
          details: err.message,
        });
      }

      console.log(`Signed IPA successfully created at: ${signedIpaPath}`);

      // 5. Extract Info.plist
      const zipSigned = new AdmZip(signedIpaPath);
      const zipEntriesSigned = zipSigned.getEntries();
      let appFolderSigned = '';

      for (const entry of zipEntriesSigned) {
        const parts = entry.entryName.split('/');
        if (parts.length > 1 && parts[1].endsWith('.app')) {
          appFolderSigned = parts[1];
          break;
        }
      }
      if (!appFolderSigned) {
        return res.status(500).json({
          error: "Couldn't find .app directory in the signed IPA.",
        });
      }

      const plistEntryPath = `Payload/${appFolderSigned}/Info.plist`;
      const plistEntry = zipSigned.getEntry(plistEntryPath);
      if (!plistEntry) {
        return res.status(500).json({ error: 'Info.plist not found in IPA.' });
      }

      const plistBuffer = plistEntry.getData();
      let plistData;
      try {
        // Try XML parsing
        plistData = plist.parse(plistBuffer.toString('utf8'));
      } catch (xmlError) {
        // Fallback to binary parse
        try {
          const parsed = await bplistParser.parseBuffer(plistBuffer);
          if (parsed && parsed.length > 0) {
            plistData = parsed[0];
          } else {
            throw new Error('Parsed binary plist is empty.');
          }
        } catch (binError) {
          console.error('Both XML and binary plist parsing failed:', binError);
          return res
            .status(500)
            .json({ error: 'Failed to parse Info.plist in signed IPA.' });
        }
      }

      const bundleId = plistData?.CFBundleIdentifier || 'com.example.unknown';
      const bundleVersion = plistData?.CFBundleVersion || '1.0.0';
      const displayName =
        plistData?.CFBundleDisplayName || plistData?.CFBundleName || 'App';

      // 6. Generate manifest plist
      const ipaUrl = new URL(
        `signed/${path.basename(signedIpaPath)}`,
        UPLOAD_URL
      ).toString();
      const manifestPlist = generateManifestPlist(
        ipaUrl,
        bundleId,
        bundleVersion,
        displayName
      );

      const filename = `${sanitizeFilename(displayName)}_${uniqueSuffix}.plist`;
      const plistPath = path.join(WORK_DIR, 'plist', filename);
      await fsp.writeFile(plistPath, manifestPlist, 'utf8');

      // 7. Generate install link
      const manifestUrl = new URL(`plist/${filename}`, UPLOAD_URL).toString();
      const installLink = `itms-services://?action=download-manifest&url=${encodeURIComponent(
        manifestUrl
      )}`;

      return res.json({ installLink });
    } catch (err) {
      console.error('Error during signing process:', err);
      return res.status(500).json({
        error: 'Unexpected error during signing. Check the server logs.',
        details: err.message,
      });
    } finally {
      // 8. Cleanup
      try {
        if (uniqueSuffix) {
          // Remove temporary IPA if it was actually uploaded (not default)
          if (
            req.files?.ipa &&
            ipaPath !== DEFAULT_IPA_PATH &&
            fs.existsSync(ipaPath)
          ) {
            await fsp.rm(ipaPath, { force: true });
          }

          // If certificates are not saved, remove them
          if (req.files?.p12 && req.files?.mobileprovision) {
            const notSaving = req.body.save_cert !== 'on';
            if (notSaving && fs.existsSync(p12Path)) {
              await fsp.rm(p12Path, { force: true });
            }
            if (notSaving && fs.existsSync(mpPath)) {
              await fsp.rm(mpPath, { force: true });
            }
          }

          // Decide whether to keep or remove the signed IPA after some time
          // If you want to remove it instantly, uncomment:
          /*
          if (fs.existsSync(signedIpaPath)) {
            await fsp.rm(signedIpaPath, { force: true });
          }
          */
        }
      } catch (cleanupErr) {
        console.error('Error during cleanup:', cleanupErr);
      }
    }
  }
);

// -- Multer Error Handling --
function multerErrorHandler(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res
        .status(413)
        .json({ error: 'File too large. Maximum allowed size is 2GB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  if (err) {
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
  return next();
}

app.use(multerErrorHandler);

// -- Start the Server --
const port = 4500;
app.listen(port, () => {
  console.log(`Server running on port ${port}.`);
});
