const { parentPort, workerData } = require('worker_threads');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

(async () => {
  const { p12Path, p12Password, mpPath, ipaPath, signedIpaPath } = workerData;
  try {
    let zsignCmd = `zsign -z 5 -k "${p12Path}" `;
    if (p12Password) zsignCmd += `-p "${p12Password}" `;
    zsignCmd += `-m "${mpPath}" -o "${signedIpaPath}" "${ipaPath}"`;
    const { stdout, stderr } = await execAsync(zsignCmd);
    parentPort.postMessage({ status: 'ok', stdout, stderr });
  } catch (error) {
    parentPort.postMessage({ status: 'error', error: error.message });
  }
})();
