# Secure Question Paper Distribution System

A highly secure, cryptographically backed web API and frontend designed for the safe distribution of examination question papers to remote exam centers.

## 🌟 Core Features

### 1. 🔐 Advanced Cryptographic Security (Hybrid Encryption)
To guarantee that intercepted papers cannot be read, the system uses a two-tier hybrid encryption model:
*   **AES-256 (GCM Mode):** Every uploaded paper is encrypted with a unique, randomly generated 256-bit AES key.
*   **RSA Key Wrapping (OAEP):** To securely transmit the AES key to the center, the key is "wrapped" (encrypted) using the Exam Center's unique **RSA Public Key** (2048-bit). This ensures that *only* the specific exam center with the matching private key can decrypt the AES key to unlock the paper.

### 2. 🧾 Digital Signatures for Authenticity
To prevent man-in-the-middle attacks or tampering:
*   **RSA-PSS Signatures:** The encrypted question paper is digitally signed using the **Admin's RSA Private Key**. 
*   Before decryption, the center mathematically verifies this signature using the Admin's Public Key. If a single byte of the file was altered in transit, the signature check fails, rejecting the paper.

### 3. ⏱️ Time-Locked Releases
Papers are strictly time-bound. When an Admin uploads a paper, they specify a `release_time`. Until that precise moment occurs, the `/center/download` API endpoints will actively block centers from downloading the paper payloads.

### 4. 👥 Role-Based Access Control (RBAC) & JWT Auth
*   **Admins:** Have the authority to upload, encrypt, sign, and securely distribute papers.
*   **Centers:** Can securely download, verify, and decrypt their assigned papers. 
*   **JWT Tokens:** All API endpoints are protected via PyJWT tokens, meaning users must authenticate with their credentials to perform any action.

### 5. 🖥️ Separate Portals for Realistic Deployment
*   **Landing Page:** A simple start page routes users to the correct role-specific portal.
*   **Admin Portal:** Dedicated page for admin login, upload, dashboards, forensics, and chain-of-custody.
*   **Center Portal:** Dedicated page for center login, assigned-paper download, signature verification, and local decryption.
*   **Separate-Machine Friendly:** Each portal can be opened on a different machine without sharing the same UI state.

### 6. 🧭 Security Dashboard, Watermark Forensics, and Chain of Custody
*   **Admin Security Dashboard:** A live view of recent audit logs, paper counts, release status, and suspicious events.
*   **Watermark Forensics:** Upload a suspected leak and inspect the embedded watermark / fingerprint for traceability.
*   **Chain of Custody Timeline:** Review the lifecycle of a paper from creation and release scheduling to download and decrypt events.
*   **Suspicious Activity Logging:** Early downloads, unauthorized access, missing files, and failed signatures are recorded in the audit log.

---

## 🏗️ System Architecture & Workflow

The architecture relies on a **Flask backend API** and a **SQLite Database (SQLAlchemy)** interacting with a unified **HTML/JS Frontend**.

**The Step-by-Step Workflow:**
1.  **Preparation phase:** Both the Admin and the Exam Centers are generated RSA Keypairs (Public/Private).
2.  **Upload & Encrypt (Admin):** 
    *   The admin uploads a PDF.
    *   The server generates an AES-256 key, embeds a per-center watermark fingerprint, encrypts the PDF, and wraps the AES key with the Center's Public Key.
    *   The server signs the encrypted data block with the Admin's Private Key and stores an audit trail.
3.  **Storage:** The encrypted `.enc` file is securely saved on disk in the `/uploads` directory, alongside metadata in the SQLite database.
4.  **Download & Verify (Center):**
    *   Once the `release_time` is reached, the Center downloads the encrypted blob, the signature, and their wrapped AES key.
    *   The payload's signature is checked against the Admin's Public Key.
5.  **Decrypt (Center):** 
    *   The AES key is unwrapped using the Center's Private Key.
    *   The original PDF is decrypted and served as a file download.
6.  **Forensics & Auditing:**
    *   The admin can inspect a leaked PDF to recover the watermark trace.
    *   The admin can review a paper's timeline to see upload, release, download, and security events.

---

## 🚀 How to Run the Project on a New System

### Prerequisites
*   **Python 3.8+** installed on your system.

### Step-by-Step Installation

**1. Navigate to the project folder:**
Open your terminal (Command Prompt, PowerShell, or bash) and navigate to the project directory:
```bash
cd path/to/project
```

**2. Create and Activate a Virtual Environment (Highly Recommended):**
This isolates the project dependencies from your entire system.
*   *On Windows:*
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```
*   *On macOS/Linux:*
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

**3. Install Dependencies:**
Install all required Python libraries via pip based on the `requirements.txt` file:
```bash
pip install -r requirements.txt
```

**4. Start the Application Server:**
Run the Flask backend server. Python will automatically create the local SQLite database (`instance/` folder) the first time it runs.
```bash
python app.py
```
*Note: The server will start running on `http://127.0.0.1:5000` via development mode.*

**5. Access the Web Interface:**
You do not need a secondary web server for the frontend. Simply locate the `index.html` file in your file explorer and double-click it to open it in any modern web browser (Chrome, Edge, Firefox). The frontend will communicate automatically with your local `http://127.0.0.1:5000` server.

---

## 🧪 Running Automated Tests and Demos

If you want to verify that the cryptography and API endpoints are working properly without manually clicking through the UI:

**Option A: Run the Demo Script**
This script will programmatically create an Admin, create a Center, encrypt a dummy paper, and decrypt it to prove the system works.
```bash
python run_demo.py
```

**Option B: Run Pytest**
To run the automated test suite located in the `tests/` folder:
```bash
pytest
```
