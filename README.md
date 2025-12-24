##### 📄 README.md

## xTCP VIEW Network Connections Dashboard

**xTCP VIEW Network Connections Dashboard** is a client–server web application that provides an **advanced view of TCP connections**, extending the functionality of Microsoft SysInternals TCP tools (`tcpview.exe`, `tcpview64.exe`, `tcpvcon.exe`, `tcpvcon64.exe`) and more.

It offers a **real‑time dashboard for monitoring network connections**, including remote DNS resolution and IP reputation checks via AbuseIPDB and VirusTotal APIs.


## 🛠️ Tech Stack

[![Python](https://img.shields.io/badge/Python-3%2B-yellow?logo=python)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-24%2B-green?logo=node.js)](https://nodejs.org/)
[![npm](https://img.shields.io/badge/npm-11%2B-red?logo=npm)](https://www.npmjs.com/)
[![React](https://img.shields.io/badge/React-18-blue?logo=react)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.x-teal?logo=tailwindcss)](https://tailwindcss.com/)
[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-darkgreen?logo=nginx)](https://nginx.org/)
[![Chrome](https://img.shields.io/badge/Browser-Chrome-blue?logo=google-chrome)](https://www.google.com/chrome/)
[![Edge](https://img.shields.io/badge/Browser-Edge-blue?logo=microsoft-edge)](https://www.microsoft.com/edge)
[![Firefox](https://img.shields.io/badge/Browser-Firefox-orange?logo=firefox)](https://www.mozilla.org/firefox/)
[![Safari](https://img.shields.io/badge/Browser-Safari-lightgrey?logo=safari)](https://www.apple.com/safari/)
[![Opera](https://img.shields.io/badge/Browser-Opera-red?logo=opera)](https://www.opera.com/)
[![License](https://img.shields.io/github/license/PrzemyslawZabicki/xtcp-view-network-connections-dashboard)](LICENSE)
[![Stars](https://img.shields.io/github/stars/PrzemyslawZabicki/xtcp-view-network-connections-dashboard?style=social)](https://github.com/PrzemyslawZabicki/xtcp-view-network-connections-dashboard/stargazers)
[![Issues](https://img.shields.io/github/issues/PrzemyslawZabicki/xtcp-view-network-connections-dashboard)](https://github.com/PrzemyslawZabicki/xtcp-view-network-connections-dashboard/issues)

---

## 💡 Features

1. **🔍 Live TCP Connection Table**  
	  
	  	Displays detailed process and connection information:

		- PID, Process Name, Path, Start Time, Command Line  
		- Protocol, Local Service, Local/Remote Ports, Status  
		- Remote IP, DNS, Country, ISP, Domain, Usage Type   

2. **⚠️ Security Lookups**  
   	
	Integrated AbuseIPDB and VirusTotal checks per remote IP:
	- AbuseIPDB: confidence score, reports, last reported  
	- VirusTotal: reputation, harmless/malicious/suspicious/undetected stats 


## 🖥️ GUI Overview

The dashboard includes:

1. **Connection & Process Information**  
2. **Network Information**  
3. **Security Intelligence**  
   - AbuseIPDB: confidence score, reports, ISP, domain, usage type, last reported  
   - VirusTotal: reputation, country, harmless/malicious/suspicious/undetected stats  

## 📂 Project Structure
```text
├── public/                 # Static assets
│   ├── favicon.ico         # Browser tab icon
│   ├── index.html          # Main HTML template
│   ├── logo192.png         # App logo (192px)
│   ├── logo512.png         # App logo (512px)
│   ├── manifest.json       # PWA manifest
│   └── robots.txt          # Search engine crawler rules
│
├── src/                    # React frontend
│   ├── App.js              # Main dashboard logic
│   ├── App.css             # Component styles
│   ├── App.test.js         # Unit tests
│   ├── index.js            # ReactDOM entry point
│   └── index.css           # Global styles (Tailwind imports)
│
├── server/                 # Python backend (FastAPI)
│   └── server.py           # API endpoints
│
├── logs/                   # Application logs
│   ├── backend.logs
│   ├── frontend.logs
│   ├── nginx-access.log
│   └── nginx-error.log
│
├── certs/                  # SSL/TLS certificates
│   ├── cert.pem
│   ├── key.pem
│   └── san.cfg             # OpenSSL SAN config
│
├── help/                   # Documentation & screenshots
│   ├── nginx.conf          # Example nginx.conf
│   └── prtsc_n.jpg(s)      # Screenshots
│
├── package.json
├── package-lock.json
├── tailwind.config.js
├── postcss.config.js
└── README.md
```

## ⚡ Quick Start
```bash
git clone https://github.com/PrzemyslawZabicki/xtcp-view-network-connections-dashboard.git
cd xtcp-view-network-connections-dashboard
```

## 🛠️ Requirements

### Backend (Server)
- Python: 3.10+
	- Dependencies:
		- psutil – process and system utilities
		- requests – HTTP client for API calls
		- certifi – trusted CA certificates for SSL/TLS validation
		- fastapi – backend framework
		- uvicorn – ASGI server

### Frontend (Client)
- Node.js: 24+
- npm: 11+

### Web Server (Nginx)
- Nginx: 1.28+


## 🔧 Installation

### === Server ===

#### 1. Verify Python
```bash
python3 --version
```

#### 2. Navigate to server directory
```bash
cd xtcp-view-network-connections-dashboard/server
```

#### 3. Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
```

#### 4. Install dependencies
```bash
pip install psutil certifi requests fastapi uvicorn
```
###### Note: certifi provides trusted CA certificates for validating SSL/TLS in AbuseIPDB and VirusTotal API calls.

#### 5. Run server
```bash
uvicorn server:app --reload --host 127.0.0.1 --port 8000
```

### === Client ===

#### 1. Verify Node.js and npm
```bash
node -v
npm -v
```

#### 2. Navigate to project root
```bash
cd xtcp-view-network-connections-dashboard
```

#### 3. Install dependencies
```bash
npm install
```

#### 4. Build production bundle
```bash
npm run build
```

#### 5. Configure .env file
```bash
DISABLE_ESLINT_PLUGIN=true
REACT_APP_API_URL=/api
ABUSEIPDB_KEY="your_abuseipdb_key"
VT_API_KEY="your_virustotal_key"
```

### === Nginx ===

#### 1. Install Nginx (download for your OS)

#### 2. Configure nginx.conf (see help/nginx.conf and replace paths with your own)

#### 3. Generate TLS certificates
```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 -nodes \
  -config certs/san.conf
```

## 📜 License
#### Licensed under the MIT License. See LICENSE.


## 🤝 Contributing
#### Pull requests are welcome.
###### For major changes, please open an issue first to discuss.

## 📧 Contact
#### Created by Przemyslaw Zabicki
##### Reach out via GitHub Issues:
##### https://github.com/PrzemyslawZabicki/xtcp-view-network-connections-dashboard/issues
