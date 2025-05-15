# Rebooter Pro API

A reusable Python library and GUI tool for interacting with Rebooter Pro devices over mutual TLS.

## Features

- HTTPS server that supports mutual TLS (mTLS)
- Secure notification subscription endpoint
- GUI for discovery and subscription
- Built-in mDNS (Zeroconf) device discovery
- Certificate verification for Rebooter devices

---

## 📦 Project Structure

```
rebooter_pro_api/
├── __init__.py
├── rebooter_gateway.py
├── rebooter_http_client.py
├── rebooter_config.py
├── gui/
│   ├── __init__.py
│   ├── app.py
│   ├── config.json
│   └── certs/
│       ├── server-cert.pem
│       ├── server-key.pem
│       └── rebooter-device-cert.pem
│   └── images/
│       ├── timing.png
│       ├── off.png
│       ├── odt.png
│       └── ardd.png
├── requirements.txt
├── README.md
├── LICENSE
└── pyproject.toml
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/your-org/rebooter-pro-api.git
cd rebooter-pro-api

# (Optional) Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🧪 Running the GUI

Make sure your `config.json` is properly configured inside the `gui/` directory. Then:

```bash
python -m rebooter_pro_api.gui.app
```

---

## 🔧 Configuration

The `config.json` file is required for launching the GUI and should be located in the `gui/` folder.

### Example `gui/config.json`:

```json
{
  "server_host": "0.0.0.0",
  "server_port": 8443,
  "server_cert_pem": "certs/server-cert.pem",
  "server_key_pem": "certs/server-key.pem",
  "rebooter_cert_pem": "certs/rebooter-device-cert.pem"
}
```

---

## 📋 Requirements

See `requirements.txt`:

```text
zeroconf
```

---

## 🔐 Certificate Requirements

You will need to provide the following PEM-formatted certificates in the `gui/certs/` directory:

**⚠️ Warning:** The sample server certificate and key included under certs/server-cert.pem and certs/server-key.pem are for demonstration only and should **not** be used in production or when building your distributable executables. You should generate your own certificates and keys before deploying or packaging.


- `server-cert.pem`: The server certificate for the local HTTPS server
- `server-key.pem`: The private key for the HTTPS server
- `rebooter-device-cert.pem`: Trusted root certificate for verifying Rebooter devices

> **⚠️ Important:** Do **not** regenerate or replace `rebooter-device-cert.pem`. This certificate must match the Rebooter device’s root certificate to verify its identity.

### Generating Your Own Certificates

```bash
# Server certificate/key for the GUI HTTPS server
openssl req -x509 -newkey rsa:2048   -keyout gui/certs/server‑key.pem   -out gui/certs/server‑cert.pem   -days 3650 -nodes   -subj "/CN=localhost"
```


---

## 🔨 Building Executables

You can convert the GUI application into a standalone executable using [PyInstaller](https://pyinstaller.org/).

### ▶️ Windows

To build a `.exe`, run the following from a Windows environment:

```cmd
python -m PyInstaller --onefile --noconsole ^
  --hidden-import=ipaddress ^
  --add-data "rebooter_pro_api/gui/config.json;." ^
  --add-data "rebooter_pro_api/gui/certs/server-cert.pem;certs" ^
  --add-data "rebooter_pro_api/gui/certs/server-key.pem;certs" ^
  --add-data "rebooter_pro_api/gui/certs/rebooter-device-cert.pem;certs" ^
  --add-data "rebooter_pro_api/gui/images;images" ^
  rebooter_pro_api/gui/app.py
```

This creates a `dist/app.exe` executable.

### ▶️ Linux / macOS

Run this from a Linux/macOS terminal to build a native ELF/macOS executable:

```bash
pyinstaller --onefile --noconsole   --hidden-import=ipaddress   --add-data "rebooter_pro_api/gui/config.json:."   --add-data "rebooter_pro_api/gui/certs/server-cert.pem:certs"   --add-data "rebooter_pro_api/gui/certs/server-key.pem:certs"   --add-data "rebooter_pro_api/gui/certs/rebooter-device-cert.pem:certs"   --add-data "rebooter_pro_api/gui/images:images"   rebooter_pro_api/gui/app.py
```

This creates a `dist/app` executable.

> ❗ You must build from the target OS. PyInstaller does not support cross-compilation by default.

---

## 🧑‍💻 Author

**Jonathan Witthoeft** – jonw@gridconnect.com

---

## 📄 License

This project is licensed under the terms of the [MIT License](LICENSE), © Grid Connect Inc.
