const { parentPort, workerData } = require('worker_threads');
const { exec } = require('child_process');
const util = require('util');
const path = require('path');

const execAsync = util.promisify(exec);

(async () => {
  const { p12Path, p12Password, mpPath, ipaPath, signedIpaPath } = workerData;

  try {
    const isWindows = process.platform === 'win32';
    const zsignExecutable = isWindows ? 'zsign.exe' : './zsign';

    let zsignCmd = `${zsignExecutable} -z 5 -k "${p12Path}" `;
    if (p12Password) zsignCmd += `-p "${p12Password}" `;
    zsignCmd += `-m "${mpPath}" -o "${signedIpaPath}" "${ipaPath}"`;
    
    const { stdout, stderr } = await execAsync(zsignCmd);
    parentPort.postMessage({ status: 'ok', stdout, stderr });

  } catch (error) {
    parentPort.postMessage({ status: 'error', error: error.message });
  }
})();