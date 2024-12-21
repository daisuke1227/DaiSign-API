# IPA Signing API (ALL CODE WAS WRITTEN USING CHATGPT O1 MINI/O1 shoutout to you :3)

Welcome to the Signing API! This API allows you to upload an IPA file, a `.p12` certificate, and a provisioning profile, and it returns a link to install the signed app.

## Features
- Upload IPA files for signing.
- Use `.p12` certificates and provisioning profiles to sign the app.
- Get an install link for the signed IPA.

## How It Works
1. Send a POST request to `/sign` with the required files.
2. The server processes the files and signs the IPA.
3. Receive an install link to download and install the signed app.

### Using this locally
If you wanna use this for your own site then change this line of the app.js ```const UPLOAD_URL = 'https://yoursite.com/'; // Update to your actual domain``` and just follow the tutorial using your own site (this part was written by Daisuke after post) 

### Changing default IPA
In the app.js code if you dont upload an ipa a ipa will automatically be used you can change that in ```const DEFAULT_IPA_PATH = path.join(__dirname, 'Portal-1.9.0.ipa'); // Ensure this file exists``` this checks if the ipa is even there so if someone doesnt upload an ipa this ipa will be used in your code you can make the ipa required so you can bypass this

## API Endpoint

### POST `/sign`

#### Parameters

| Name            | Type   | Required | Description                                      |
|------------------|--------|----------|--------------------------------------------------|
| `ipa`           | File   | No       | The IPA file to be signed. Optional if default IPA is used. |
| `p12`           | File   | Yes      | The `.p12` certificate file for signing.         |
| `mobileprovision` | File   | Yes      | The provisioning profile file.                  |
| `p12_password`  | String | No       | The password for the `.p12` certificate (if required). |

## Example Usage

### Curl
```bash
curl -X POST https://api.ipasign.pro/sign \
-F "ipa=@/path/to/app.ipa" \
-F "p12=@/path/to/cert.p12" \
-F "mobileprovision=@/path/to/profile.mobileprovision" \
-F "p12_password=your_password"
```
### Python
```
import requests

url = "https://api.ipasign.pro/sign"
files = {
    'ipa': open('/path/to/app.ipa', 'rb'),
    'p12': open('/path/to/cert.p12', 'rb'),
    'mobileprovision': open('/path/to/profile.mobileprovision', 'rb'),
}
data = {'p12_password': 'your_password'}

response = requests.post(url, files=files, data=data)
print(response.json())
```
### JavaScript (Node.js) 
```
const FormData = require('form-data');
const axios = require('axios');
const fs = require('fs');

const form = new FormData();
form.append('ipa', fs.createReadStream('/path/to/app.ipa'));
form.append('p12', fs.createReadStream('/path/to/cert.p12'));
form.append('mobileprovision', fs.createReadStream('/path/to/profile.mobileprovision'));
form.append('p12_password', 'your_password');

axios.post('https://api.ipasign.pro/sign', form, {
    headers: form.getHeaders(),
})
.then(response => console.log(response.data))
.catch(error => console.error(error));
```

### HTML/JS (use for websites and a starting base)
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IPA Signer</title>
</head>
<body>
    <h2>IPA Signer</h2>
    <form id="signForm" action="https://api.ipasign.pro/sign" method="POST" enctype="multipart/form-data">
        <p>
            <label for="ipa">IPA File (.ipa) <small>(Optional)</small></label><br>
            <input type="file" id="ipa" name="ipa" accept=".ipa">
        </p>
        <p>
            <label for="p12">Certificate File (.p12) <small>(Required)</small></label><br>
            <input type="file" id="p12" name="p12" accept=".p12" required>
        </p>
        <p>
            <label for="mobileprovision">Provisioning Profile (.mobileprovision) <small>(Required)</small></label><br>
            <input type="file" id="mobileprovision" name="mobileprovision" accept=".mobileprovision" required>
        </p>
        <p>
            <label for="p12_password">P12 Password <small>(Optional)</small></label><br>
            <input type="password" id="p12_password" name="p12_password" placeholder="Enter P12 Password">
        </p>
        <p>
            <button type="submit">Sign IPA</button>
        </p>
    </form>

    <!-- Popup container -->
    <div id="popupContainer"></div>

    <script>
        document.addEventListener("DOMContentLoaded", () => {
            const form = document.getElementById("signForm");

            const popupContainer = document.getElementById("popupContainer");

            const adjustPopupSize = () => {
                popupContainer.style.width = window.innerWidth < 600 ? "80%" : "400px";
                popupContainer.style.maxWidth = "90%";
                popupContainer.style.top = "50%";
                popupContainer.style.left = "50%";
                popupContainer.style.transform = "translate(-50%, -50%)";
                popupContainer.style.position = "fixed";
                popupContainer.style.backgroundColor = "#fff";
                popupContainer.style.border = "1px solid #ccc";
                popupContainer.style.boxShadow = "0 2px 10px rgba(0, 0, 0, 0.2)";
                popupContainer.style.zIndex = "1000";
                popupContainer.style.padding = "10px";
                popupContainer.style.textAlign = "center";
            };

            window.addEventListener("resize", adjustPopupSize);

            form.addEventListener("submit", async (e) => {
                e.preventDefault();
                const formData = new FormData(form);

                try {
                    const response = await fetch(form.action, {
                        method: "POST",
                        body: formData,
                    });

                    if (!response.ok) {
                        throw new Error("Failed to sign the IPA. Please try again.");
                    }

                    const data = await response.json();

                    if (data.installLink) {
                        popupContainer.innerHTML = `
                            <h3>Signing Complete</h3>
                            <p>Your signed IPA is ready. Click the link below to install:</p>
                            <a href="${data.installLink}" target="_blank">${data.installLink}</a>
                            <br><br>
                            <button onclick="document.getElementById('popupContainer').style.display='none'">Close</button>
                        `;
                        popupContainer.style.display = "block";
                        adjustPopupSize();
                    } else {
                        throw new Error("Invalid response from the server.");
                    }
                } catch (error) {
                    popupContainer.innerHTML = `
                        <h3>Error</h3>
                        <p>${error.message}</p>
                        <button onclick="document.getElementById('popupContainer').style.display='none'">Close</button>
                    `;
                    popupContainer.style.display = "block";
                    adjustPopupSize();
                }
            });
        });
    </script>
</body>
</html>
```
### Example Response
```
{
  "installLink": "itms-services://?action=download-manifest&url=https://api.ipasign.pro/plist/example.plist"
}
```
Field	Description
installLink	The link to download and install the signed app.

Common Errors

Missing Required Files

{
  "error": "P12 and MobileProvision files are required."
}

	•	Cause: You did not upload the .p12 or .mobileprovision file.
	•	Fix: Ensure both files are included in your request.

Notes
	•	The ipa file is optional. If not provided, the default IPA will be used.
	•	The p12_password is only required if your certificate has a password.

Credits
	•	API Developed By: Daisuke
	•	Documentation Assistance: ChatGPT

Questions or Issues?

If you have any questions or run into issues, feel free to reach out to Daisuke on [Discord](https://discord.com/users/630151942135480370) or [Telegram](https://t.me/dai1228)

