const { parentPort, workerData } = require('worker_threads');
const { exec } = require('child_process');

/**
 * workerData structure:
 * {
 *   p12Path: string,
 *   p12Password: string,
 *   mpPath: string,
 *   ipaPath: string,
 *   signedIpaPath: string
 * }
 */

(async () => {
  const { p12Path, p12Password, mpPath, ipaPath, signedIpaPath } = workerData;

  try {
    // Build zsign command
    let zsignCmd = `zsign -z 5 -k "${p12Path}" `;
    if (p12Password) {
      zsignCmd += `-p "${p12Password}" `;
    }
    zsignCmd += `-m "${mpPath}" -o "${signedIpaPath}" "${ipaPath}"`;

    // Execute zsign
    const { stdout, stderr } = await execAsync(zsignCmd);
    // If successful, send a message back
    parentPort.postMessage({ status: 'ok', stdout, stderr });
  } catch (error) {
    // On error, inform main thread
    parentPort.postMessage({ status: 'error', error: error.message });
  }
})();

// A small helper to promisify exec
function execAsync(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        return reject(new Error(stderr || error.message));
      }
      resolve({ stdout, stderr });
    });
  });
}
