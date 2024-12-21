# IPA Signing API

Welcome to the IPA Signing API! This API allows you to upload an IPA file, a `.p12` certificate, and a provisioning profile, and it returns a link to install the signed app.

## Features
- Upload IPA files for signing.
- Use `.p12` certificates and provisioning profiles to sign the app.
- Get an install link for the signed IPA.

## How It Works
1. Send a POST request to `/sign` with the required files.
2. The server processes the files and signs the IPA.
3. Receive an install link to download and install the signed app.

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
### Example Response

```{
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

If you have any questions or run into issues, feel free to reach out to Daisuke at your_email@example.com.

