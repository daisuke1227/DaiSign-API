const express = require('express');
const multer = require('multer');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { exec } = require('child_process');
const AdmZip = require('adm-zip');
const plist = require('plist');
const bplistParser = require('bplist-parser');
const crypto = require('crypto'); // For encryption and decryption
const cors = require('cors'); // Enable CORS for all origins

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // Allow all origins

// **Serve static files from the 'public' directory**
app.use(express.static(path.join(__dirname, 'public')));

// Hardcoded Configuration Variables
const UPLOAD_URL = 'https://yoursite.com/'; // Update to your actual domain
const WORK_DIR = path.join(__dirname, 'uploads'); // Ensure this directory exists or will be created
const ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 64-character hex string (32 bytes)

// Validate Encryption Key
if (Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error("Error: ENCRYPTION_KEY must be a 64-character hexadecimal string (32 bytes).");
  process.exit(1);
}

// Path to the default IPA
const DEFAULT_IPA_PATH = path.join(__dirname, 'Portal-1.9.0.ipa'); // Ensure this file exists

// Check if default IPA exists
if (!fs.existsSync(DEFAULT_IPA_PATH)) {
  console.error(`Error: Default IPA not found at path: ${DEFAULT_IPA_PATH}`);
  process.exit(1);
}

// Ensure necessary directories exist
const dirs = ['p12', 'mp', 'temp', 'signed', 'plist'];
for (const d of dirs) {
  const dirPath = path.join(WORK_DIR, d);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
    console.log(`Created directory: ${dirPath}`);
  }
}

// Serve static files for signed IPAs and plist manifests
app.use('/signed', express.static(path.join(WORK_DIR, 'signed')));
app.use('/plist', express.static(path.join(WORK_DIR, 'plist')));

// Multer configuration for file uploads with 2GB limit
const upload = multer({
  dest: path.join(WORK_DIR, 'temp'),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }, // 2 GB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['.ipa', '.p12', '.mobileprovision'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only .ipa, .p12, and .mobileprovision are allowed.'));
    }
  }
});

// Generate a unique suffix to prevent filename clashes
function generateRandomSuffix() {
  const randomStr = Math.random().toString(36).substring(2, 8); // 6-character random string
  return Date.now() + '_' + randomStr;
}

// Helper function to delete old files
async function deleteOldFiles(directory, maxAgeInMs) {
  try {
    const files = await fsp.readdir(directory);
    const now = Date.now();

    for (const file of files) {
      const filePath = path.join(directory, file);
      try {
        const stats = await fsp.stat(filePath);
        const fileAge = now - stats.mtimeMs;

        if (fileAge > maxAgeInMs) {
          await fsp.unlink(filePath);
          console.log(`Deleted file: ${filePath}`);
        }
      } catch (err) {
        console.error(`Error processing file ${filePath}:`, err);
      }
    }
  } catch (err) {
    console.error(`Error reading directory ${directory}:`, err);
  }
}

// Define directories to clean
const directoriesToClean = ['mp', 'p12', 'plist', 'temp', 'signed'].map(dir => path.join(WORK_DIR, dir));

// Define cleanup interval and file max age (30 minutes)
const CLEANUP_INTERVAL_MS = 30 * 60 * 1000; // 30 minutes
const MAX_FILE_AGE_MS = 30 * 60 * 1000;    // 30 minutes

// Function to perform cleanup
async function performCleanup() {
  console.log('Starting cleanup process...');
  for (const dir of directoriesToClean) {
    await deleteOldFiles(dir, MAX_FILE_AGE_MS);
  }
  console.log('Cleanup process completed.');
}

// Schedule the cleanup to run every 30 minutes
setInterval(performCleanup, CLEANUP_INTERVAL_MS);

// Optionally, run cleanup immediately on server start
performCleanup();

// Helper function to execute shell commands with Promises
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

// Helper function to sanitize filenames
function sanitizeFilename(name) {
  return name.replace(/[^a-zA-Z0-9_-]/g, '');
}

// Function to generate the manifest plist
function generateManifestPlist(ipaUrl, bundleId, bundleVersion, displayName) {
  const defaultBundleId = 'com.example.default'; // Replace with your default bundle identifier if needed

  const plistContent = `<?xml version="1.0" encoding="UTF-8"?>
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
                    <string>${bundleId ? bundleId : defaultBundleId}</string>
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
  return plistContent;
}

// Encryption Functionality
const algorithm = 'aes-256-cbc';
const key = Buffer.from(ENCRYPTION_KEY, 'hex'); // 32 bytes key
const ivLength = 16; // AES block size

function encrypt(text) {
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  // Return iv and encrypted data
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  const parts = encryptedText.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid encrypted text format');
  }
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// POST /sign route
app.post('/sign', upload.fields([
  { name: 'ipa', maxCount: 1 }, // IPA is optional
  { name: 'p12', maxCount: 1 },
  { name: 'mobileprovision', maxCount: 1 }
]), async (req, res) => {
  let uniqueSuffix;
  let ipaPath;
  let signedIpaPath;
  let p12Path;
  let mpPath;
  let outputIpaPath; // To track the output IPA from zsign
  let encryptedPassword = null; // To store the encrypted password if saving

  console.log('Sign Request Received');

  try {
    const p12Password = req.body.p12_password; // Password is optional when uploading new certs
    const saveCert = req.body.save_cert === 'on'; // Checkbox value

    // Determine the input IPA path
    if (req.files['ipa']) {
      uniqueSuffix = generateRandomSuffix();
      ipaPath = path.join(WORK_DIR, 'temp', `input_${uniqueSuffix}.ipa`);
      await fsp.rename(req.files['ipa'][0].path, ipaPath);
      outputIpaPath = ipaPath;
      console.log(`Received IPA: ${req.files['ipa'][0].originalname}`);
    } else {
      ipaPath = DEFAULT_IPA_PATH;
      outputIpaPath = ipaPath;
      console.log(`No IPA uploaded. Using default IPA at: ${DEFAULT_IPA_PATH}`);
    }

    // Handle certificate uploads
    if (req.files['p12'] && req.files['mobileprovision']) {
      uniqueSuffix = generateRandomSuffix();
      if (saveCert) {
        // Save certificates permanently
        p12Path = path.join(WORK_DIR, 'p12', `cert_${uniqueSuffix}.p12`);
        mpPath = path.join(WORK_DIR, 'mp', `app_${uniqueSuffix}.mobileprovision`);
        await fsp.rename(req.files['p12'][0].path, p12Path);
        await fsp.rename(req.files['mobileprovision'][0].path, mpPath);
        console.log(`Saved certificates: ${p12Path}, ${mpPath}`);

        // Encrypt and save the password if provided
        if (p12Password && p12Password.trim() !== '') {
          encryptedPassword = encrypt(p12Password);
          const passwordPath = path.join(WORK_DIR, 'p12', `password_${uniqueSuffix}.enc`);
          await fsp.writeFile(passwordPath, encryptedPassword, 'utf8');
          console.log(`Saved encrypted password at: ${passwordPath}`);
        } else {
          console.log(`No password provided. Certificates saved without a password.`);
        }
      } else {
        // Use certificates temporarily
        p12Path = path.join(WORK_DIR, 'p12', `cert_${uniqueSuffix}.p12`);
        mpPath = path.join(WORK_DIR, 'mp', `app_${uniqueSuffix}.mobileprovision`);
        await fsp.rename(req.files['p12'][0].path, p12Path);
        await fsp.rename(req.files['mobileprovision'][0].path, mpPath);
        console.log(`Received temporary certificates: ${p12Path}, ${mpPath}`);
      }
    } else {
      return res.status(400).json({ error: "P12 and MobileProvision files are required." });
    }

    // Define the signed IPA path
    signedIpaPath = path.join(WORK_DIR, 'signed', `signed_${uniqueSuffix}.ipa`);

    try {
      // Initialize the zsign command with default options
      let zsignCmd = `zsign -c 5 -k "${p12Path}" `;

      // Add the optional password argument if provided
      if (p12Password && p12Password.trim() !== '') {
        zsignCmd += `-p "${p12Password}" `;
      }

      // Add the mobileprovision and output paths
      zsignCmd += `-m "${mpPath}" -o "${signedIpaPath}" `;

      // Append the input IPA path
      zsignCmd += `"${outputIpaPath}"`;

      console.log(`Executing zsign command: ${zsignCmd}`);

      // Execute the zsign command
      await execPromise(zsignCmd);

      console.log(`Signed IPA successfully created at: ${signedIpaPath}`);
    } catch (err) {
      console.error('Error executing zsign command:', err);
      throw new Error(`zsign failed with error: ${err.message}`);
    }

    // Extract Info.plist from the signed IPA for manifest generation
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
      return res.status(500).json({ error: "Couldn't find .app directory in the signed IPA." });
    }

    const plistEntryPathSigned = `Payload/${appFolderSigned}/Info.plist`;
    const plistEntrySigned = zipSigned.getEntry(plistEntryPathSigned);
    if (!plistEntrySigned) {
      return res.status(500).json({ error: "Info.plist not found in the signed IPA." });
    }

    const plistBufferSigned = plistEntrySigned.getData();
    let plistDataSigned;

    try {
      // Attempt to parse as XML plist
      plistDataSigned = plist.parse(plistBufferSigned.toString('utf8'));
    } catch (xmlParseError) {
      try {
        // If XML parsing fails, attempt to parse as binary plist
        const parsed = await bplistParser.parseBuffer(plistBufferSigned);
        if (parsed && parsed.length > 0) {
          plistDataSigned = parsed[0];
        } else {
          throw new Error("Parsed binary plist is empty.");
        }
      } catch (binaryParseError) {
        console.error("Both XML and binary plist parsing failed:", binaryParseError);
        return res.status(500).json({ error: "Failed to parse Info.plist." });
      }
    }

    const bundleId = plistDataSigned['CFBundleIdentifier'] || 'com.example.unknown';
    const bundleVersion = plistDataSigned['CFBundleVersion'] || '1.0.0';
    const displayName = plistDataSigned['CFBundleDisplayName'] || plistDataSigned['CFBundleName'] || 'App';

    // Generate manifest plist
    const ipaUrl = new URL(`signed/${path.basename(signedIpaPath)}`, UPLOAD_URL).toString();
    const manifestPlist = generateManifestPlist(
      ipaUrl,
      bundleId,
      bundleVersion,
      displayName
    );

    // Save the manifest plist
    const filename = sanitizeFilename(displayName) + '_' + uniqueSuffix + '.plist';
    const plistPath = path.join(WORK_DIR, 'plist', filename);
    await fsp.writeFile(plistPath, manifestPlist, 'utf8');
    console.log(`Generated manifest plist at: ${plistPath}`);

    // Generate the install link
    const manifestUrl = new URL(`plist/${filename}`, UPLOAD_URL).toString();
    const installLink = `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
    console.log(`Generated install link: ${installLink}`);

    // Respond with JSON containing the install link
    res.json({ installLink });
  } catch (err) {
    console.error('Error during signing process:', err);
    res.status(500).json({ error: err.message });
  } finally {
    try {
      // Define paths based on uniqueSuffix
      if (uniqueSuffix) {
        const signedIpa = path.join(WORK_DIR, 'signed', `signed_${uniqueSuffix}.ipa`);

        // Remove uploaded IPA if it was uploaded and not using the default IPA
        if (req.files['ipa'] && ipaPath !== DEFAULT_IPA_PATH && fs.existsSync(ipaPath)) {
          await fsp.rm(ipaPath, { force: true });
          console.log(`Removed uploaded IPA at: ${ipaPath}`);
        }

        // Remove temporary certificates if not saved
        if (!(req.body.save_cert === 'on') && p12Path && mpPath) {
          if (fs.existsSync(p12Path)) {
            await fsp.rm(p12Path, { force: true });
            console.log(`Removed temporary P12 at: ${p12Path}`);
          }
          if (fs.existsSync(mpPath)) {
            await fsp.rm(mpPath, { force: true });
            console.log(`Removed temporary MobileProvision at: ${mpPath}`);
          }
        }

        // Optionally, remove signed IPA after a certain period or based on requirements
        // If you want to keep the signed IPA, comment out the following lines
        /*
        if (fs.existsSync(signedIpa)) {
          await fsp.rm(signedIpa, { force: true });
        }
        */

        console.log('Cleaned up temporary files.');
      }
    } catch (cleanupErr) {
      console.error('Error during cleanup:', cleanupErr);
    }
  }
});

// Enhanced error handling middleware for Multer
function multerErrorHandler(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    // Handle Multer-specific errors
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum allowed size is 2GB.' });
    }
    // Handle other Multer errors if necessary
    return res.status(400).json({ error: err.message });
  } else if (err) {
    // Handle other errors
    return res.status(500).json({ error: 'An unexpected error occurred.' });
  }
  next();
}

// Apply the error handling middleware after all routes
app.use(multerErrorHandler);

// Start the server on port 3002
const port = 4500;
app.listen(port, () => {
  console.log(`Server running on port ${port}.`);
});
