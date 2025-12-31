# 🔒 File Integrity Checker (iChecker)

<div align="center">

![Java](https://img.shields.io/badge/Java-8+-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)
![Security](https://img.shields.io/badge/Security-PKI-red?style=for-the-badge&logo=security&logoColor=white)
![RSA](https://img.shields.io/badge/RSA-2048--bit-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

**Enterprise-grade directory integrity monitoring system using RSA digital signatures and cryptographic hashing**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Security](#-security) • [Documentation](#-technical-architecture)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Security Architecture](#-security-architecture)
- [Installation](#-installation)
- [Usage Guide](#-usage-guide)
  - [Creating Key Pair](#1-create-public-private-key-pair--certificate)
  - [Creating Registry](#2-create-registry-file)
  - [Checking Integrity](#3-check-directory-integrity)
- [Technical Architecture](#-technical-architecture)
- [Implementation Details](#-implementation-details)
- [Project Structure](#-project-structure)
- [Academic Context](#-academic-context)
- [Security Considerations](#-security-considerations)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## 🎯 Overview

**iChecker** is a sophisticated file integrity monitoring system that provides **enterprise-level security** for detecting unauthorized changes to files and directories. It combines multiple cryptographic techniques to ensure data integrity and authenticity:

- **RSA 2048-bit** public/private key pairs for digital signatures
- **X.509 self-signed certificates** for public key distribution
- **AES encryption** for secure private key storage
- **MD5/SHA-256 hashing** for file integrity verification
- **Digital signatures** for registry authentication

**Use Cases:**
- Monitor critical system files for tampering
- Detect unauthorized modifications in sensitive directories
- Maintain audit trail of file changes
- Verify integrity of configuration files
- Ensure compliance with security policies

---

## ✨ Features

### 🔐 Cryptographic Security

- ✅ **RSA 2048-bit Key Generation** - Industry-standard asymmetric encryption
- ✅ **X.509 Self-Signed Certificates** - PKI infrastructure implementation
- ✅ **Digital Signatures** - SHA-256 with RSA for registry authentication
- ✅ **AES Encryption** - Secure private key storage with password protection
- ✅ **MD5-Derived Keys** - Password-based key derivation for AES
- ✅ **Dual Hash Support** - MD5 or SHA-256 for file integrity

### 🛡️ Integrity Monitoring

- ✅ **Automated Detection** - Identifies created, altered, and deleted files
- ✅ **Registry-Based Tracking** - Maintains cryptographic hashes of all files
- ✅ **Signature Verification** - Validates registry file authenticity
- ✅ **Timestamped Audit Logs** - Complete audit trail of all operations
- ✅ **Recursive Directory Scanning** - Monitors entire directory trees
- ✅ **Password-Protected Operations** - Secure access to private keys

### 💻 Enterprise Features

- ✅ **Command-Line Interface** - Easy integration with scripts and automation
- ✅ **Java Keytool Integration** - Leverages standard Java cryptographic tools
- ✅ **Flexible Configuration** - Customizable hash algorithms and paths
- ✅ **Comprehensive Logging** - Detailed operation logs with timestamps
- ✅ **Error Handling** - Robust validation and error messages

---

## 🔐 Security Architecture

### Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    iChecker Security Flow                    │
└─────────────────────────────────────────────────────────────┘

1. KEY GENERATION
   User Password → MD5 Hash → AES Key
   Java Keytool → RSA 2048-bit Key Pair
   Private Key → AES Encrypt → Encrypted File
   Public Key → X.509 Certificate (Self-Signed)

2. REGISTRY CREATION
   Directory Files → Hash (MD5/SHA-256) → Registry Map
   Registry Content → Hash → RSA Sign → Digital Signature
   Registry File = [File Paths + Hashes] + [Signature]

3. INTEGRITY VERIFICATION
   Registry File → Extract Signature
   Public Key (from Certificate) → Verify Signature
   If Valid: Compare File Hashes
   If Invalid: Log Error & Exit
   Changes Detected → Log Results
```

### Cryptographic Components

#### 1. RSA Key Pair Generation
```java
keytool -genkeypair -alias ichecker-cert -keyalg RSA -keysize 2048
        -validity 365 -keystore [privateKeyPath] -storetype PKCS12
```

#### 2. Private Key Protection
```
Password → MD5(password) → AES-128 Key
Private Key + "PRIVATEKEY" marker → AES Encrypt → Encrypted File
```

#### 3. Digital Signature
```
Registry Content → SHA-256 Hash → RSA Sign (Private Key) → Signature
Verification: Signature + Public Key → Verify → True/False
```

---

## 🚀 Installation

### Prerequisites

- **Java 8 or higher**
- **Java Keytool** (included with JDK)
- **javax.crypto package** (standard Java library)

### Download and Compile

```bash
# Clone repository
git clone https://github.com/memo-13-byte/file-integrity-checker.git
cd file-integrity-checker

# Compile Java source
javac src/ichecker.java

# Verify compilation
java -cp src ichecker
```

---

## 💡 Usage Guide

### 1. Create Public/Private Key Pair & Certificate

Generate RSA keys and X.509 certificate:

```bash
java -cp src ichecker createCert -k private.key -c certificate.crt
```

**Parameters:**
- `-k` - Path for encrypted private key file
- `-c` - Path for X.509 certificate file

**Interactive Prompt:**
```
Enter password for keystore:
[User enters password - used for AES encryption]
```

**What Happens:**
1. Generates 2048-bit RSA key pair
2. Creates self-signed X.509 certificate (valid 365 days)
3. Encrypts private key with AES using MD5(password)
4. Saves encrypted private key to `private.key`
5. Exports certificate to `certificate.crt`

---

### 2. Create Registry File

Monitor a directory by creating a registry:

```bash
java -cp src ichecker createReg -r registry.reg -p /path/to/monitor \
     -l audit.log -h SHA-256 -k private.key
```

**Parameters:**
- `-r` - Registry file path
- `-p` - Directory to monitor
- `-l` - Log file path
- `-h` - Hash algorithm (`MD5` or `SHA-256`)
- `-k` - Encrypted private key file

**Interactive Prompt:**
```
Enter password to decrypt private key:
[User enters password - must match key creation password]
```

**Registry File Format:**
```
/path/to/file1.txt dGVzdCBmaWxlIGhhc2g=
/path/to/file2.doc YW5vdGhlciBoYXNo
/path/to/file3.pdf bW9yZSBoYXNoZXM=
#signature#
MEUCIQDXxH8... [Base64 encoded RSA signature]
```

**Log File Output:**
```
31-12-2024 14:30:15: Registry file is created at /path/registry.reg!
31-12-2024 14:30:15: /path/to/file1.txt is added to registry.
31-12-2024 14:30:15: /path/to/file2.doc is added to registry.
31-12-2024 14:30:15: /path/to/file3.pdf is added to registry.
31-12-2024 14:30:16: 3 files are added to the registry and registry creation is finished!
```

---

### 3. Check Directory Integrity

Verify if files have been modified, added, or deleted:

```bash
java -cp src ichecker check -r registry.reg -p /path/to/monitor \
     -l audit.log -h SHA-256 -c certificate.crt
```

**Parameters:**
- `-r` - Registry file to verify
- `-p` - Directory to check
- `-l` - Log file path
- `-h` - Hash algorithm (must match registry creation)
- `-c` - Certificate file (for signature verification)

**Verification Process:**
1. ✅ Verify registry signature using public key from certificate
2. ✅ If signature invalid → Log error and exit
3. ✅ If signature valid → Compare file hashes
4. ✅ Detect changes: created, altered, deleted
5. ✅ Log all changes with timestamps

**Example Output (Changes Detected):**
```
31-12-2024 15:45:22: /path/to/file1.txt is altered
31-12-2024 15:45:22: /path/to/file4.pdf is created
31-12-2024 15:45:22: /path/to/file2.doc is deleted
```

**Example Output (No Changes):**
```
31-12-2024 15:45:22: The directory is checked and no change is detected!
```

**Example Output (Invalid Signature):**
```
31-12-2024 15:45:22: Registry file verification failed!
[Program terminates]
```

---

## 🔬 Technical Architecture

### Component Diagram

```
┌──────────────────────────────────────────────────────────┐
│                    iChecker Components                    │
└──────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Key Generator  │───▶│  Private Key     │◀──▶│  AES Encryptor  │
│  (RSA 2048)     │    │  Storage (AES)   │    │  (MD5 + AES)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │
        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Certificate    │───▶│  Public Key      │───▶│  Signature      │
│  Generator      │    │  Distribution    │    │  Verifier       │
│  (X.509)        │    │  (Certificate)   │    │  (SHA256+RSA)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
        ┌────────────────────────────────────────────────┘
        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  File Scanner   │───▶│  Hash Generator  │───▶│  Registry File  │
│  (Directory)    │    │  (MD5/SHA-256)   │    │  (Signed)       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                                                │
        ▼                                                ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Integrity      │───▶│  Change          │───▶│  Audit Log      │
│  Checker        │    │  Detector        │    │  (Timestamped)  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Cryptographic Flow

#### Key Generation & Storage
```java
1. Generate RSA Key Pair (2048-bit)
   KeyPairGenerator.getInstance("RSA").generateKeyPair()

2. Create Self-Signed X.509 Certificate
   keytool -genkeypair -keyalg RSA -keysize 2048

3. Encrypt Private Key
   Password → MD5 → AES Key
   PrivateKey + "PRIVATEKEY" → AES Encrypt → File

4. Export Certificate
   keytool -exportcert -alias ichecker-cert
```

#### Registry Creation
```java
1. Decrypt Private Key
   User Password → MD5 → AES Key
   Encrypted File → AES Decrypt → Private Key

2. Hash All Files
   For each file:
     File Content → Hash Algorithm → Base64 Hash
     Store: FilePath → Hash

3. Sign Registry
   Registry Content → SHA-256 → Hash
   Hash → RSA Sign (Private Key) → Signature
   Registry = Content + "#signature#" + Base64(Signature)
```

#### Integrity Verification
```java
1. Verify Signature
   Extract Signature from Registry
   Public Key (Certificate) → Verify Signature
   If invalid: Exit with error

2. Compare Hashes
   For each current file:
     Compute Hash → Compare with Registry
   Detect: Created, Altered, Deleted

3. Log Results
   Write changes to audit log with timestamps
```

---

## 🛠️ Implementation Details

### Core Classes and Methods

#### 1. `createKeyPair()`
**Purpose:** Generate RSA key pair and X.509 certificate

```java
// Key generation using Java Keytool
keytool -genkeypair -alias ichecker-cert -keyalg RSA -keysize 2048
        -validity 365 -keystore [path] -storetype PKCS12

// Certificate export
keytool -exportcert -alias ichecker-cert -keystore [path]
        -file [certificatePath]

// Private key encryption
Password → MD5 → AES Key → Encrypt(PrivateKey + "PRIVATEKEY")
```

#### 2. `createRegistry()`
**Purpose:** Create signed registry of directory files

```java
// Password verification and key decryption
MD5(password) → AES Key → Decrypt(PrivateKeyFile)

// File hashing
For each file in directory:
  FileContent → Hash(MD5/SHA-256) → Base64Encode

// Registry signing
RegistryContent → SHA256 → RSASign(PrivateKey) → Signature
RegistryFile = Content + "#signature#" + Base64(Signature)
```

#### 3. `checkIntegrity()`
**Purpose:** Verify directory integrity using registry

```java
// Signature verification
Extract Signature from Registry
PublicKey(Certificate) → Verify(Signature, Content)

// Change detection
CurrentFiles = Hash all current files
For each file in Registry:
  if not in CurrentFiles: Log "deleted"
  if hash different: Log "altered"
For each file in CurrentFiles:
  if not in Registry: Log "created"
```

### Helper Functions

#### `hashFile(String filePath, String algorithm)`
Computes file hash using MD5 or SHA-256

#### `aesEncrypt(byte[] data, String password, byte[] iv)`
Encrypts data using AES with MD5-derived key

#### `aesDecrypt(byte[] data, String password)`
Decrypts AES-encrypted data

#### `getPrivateKey(String privateKeyPath, char[] storePassword)`
Retrieves private key from PKCS12 keystore

#### `verifySignature(String registryPath, String certificatePath)`
Verifies registry signature using X.509 certificate

#### `logMessage(String logPath, String message)`
Writes timestamped messages to audit log

---

## 📁 Project Structure

```
file-integrity-checker/
│
├── src/
│   └── ichecker.java           # Main implementation
│
├── BBM465_Fall_24_Assignment_2.pdf  # Assignment specification
├── report.pdf                  # Technical documentation
├── LICENSE                     # MIT License
├── .gitignore                  # Git ignore rules
└── README.md                   # This file
```

---

## 🎓 Academic Context

**Course:** BBM 465 - Information Security Laboratory  
**Institution:** Hacettepe University, Computer Engineering Department  
**Semester:** Fall 2024  
**Group:** 28  
**Team Members:**
- Mehmet Yiğit (b2210356159)
- Mehmet Oğuz Kocadere (b2210356021)

**Topics Covered:**
- Public Key Infrastructure (PKI)
- Digital signatures and certificates
- X.509 certificate standards
- RSA asymmetric encryption
- AES symmetric encryption
- Cryptographic hashing (MD5, SHA-256)
- File integrity monitoring
- Secure key management

---

## ⚠️ Security Considerations

### Strengths ✅

1. **Strong Cryptography**
   - RSA 2048-bit keys (industry standard)
   - SHA-256 hashing for signatures
   - AES encryption for private keys

2. **Tamper Detection**
   - Digital signatures prevent registry modification
   - Cryptographic hashes detect file changes
   - Signature verification before integrity check

3. **Secure Key Storage**
   - Password-protected private keys
   - AES encryption with MD5-derived keys
   - Meaningful plaintext for password validation

4. **Comprehensive Logging**
   - Timestamped audit trail
   - All operations logged
   - Change detection documented

### Limitations ⚠️

1. **MD5 for Password Hashing**
   - **Issue:** MD5 is cryptographically broken
   - **Production Fix:** Use bcrypt, scrypt, or Argon2
   - **Note:** Acceptable for educational purposes

2. **Self-Signed Certificates**
   - **Issue:** No chain of trust
   - **Production Fix:** Use Certificate Authority (CA)
   - **Note:** Suitable for local/internal use

3. **Password Storage**
   - **Issue:** No salt in key derivation
   - **Production Fix:** Use PBKDF2 with salt
   - **Note:** Educational implementation

4. **TOCTOU Attacks**
   - **Issue:** Time-of-check-time-of-use vulnerability
   - **Production Fix:** Atomic operations, file locking
   - **Note:** Outside assignment scope

### Production Recommendations

For enterprise deployment:

```java
// Instead of MD5 for passwords:
PBKDF2WithHmacSHA256 + Salt + High iteration count

// Instead of self-signed certs:
Certificate Authority (Let's Encrypt, corporate CA)

// Additional features:
- Real-time monitoring (inotify, FileSystemWatcher)
- Database storage for large deployments
- Role-based access control
- Network-based centralized monitoring
```

---

## 🎯 Learning Outcomes

By studying this project, you will master:

### 1. Public Key Infrastructure (PKI)
- RSA key pair generation
- X.509 certificate creation
- Self-signed vs. CA-signed certificates
- Certificate validation and chains of trust

### 2. Digital Signatures
- Signature creation with RSA
- Signature verification process
- Hash-then-sign paradigm
- Non-repudiation concepts

### 3. Symmetric Encryption
- AES encryption/decryption
- Key derivation from passwords
- Initialization vectors (IV)
- CBC mode with PKCS5 padding

### 4. Cryptographic Hashing
- MD5 vs. SHA-256 trade-offs
- Hash function properties
- File integrity verification
- Collision resistance

### 5. Secure Software Development
- Java security APIs
- Keytool command-line usage
- Error handling in crypto code
- Secure key management

### 6. File System Security
- Integrity monitoring systems
- Change detection algorithms
- Audit logging best practices
- Recursive directory traversal

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

1. **Replace MD5 password hashing** with bcrypt/scrypt
2. **Add GUI interface** for easier use
3. **Implement real-time monitoring** with file system watchers
4. **Add support for CA-signed certificates**
5. **Create database backend** for large-scale deployments
6. **Add email/SMS alerts** for detected changes

### How to Contribute

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -m 'Add improvement'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Mehmet Oğuz Kocadere**

- 🎓 Computer Engineering Student @ Hacettepe University
- 🔒 Focus: Cybersecurity, PKI, Network Security
- 💼 [LinkedIn](https://linkedin.com/in/mehmet-oguz-kocadere)
- 📧 Email: canmehmetoguz@gmail.com
- 🌐 GitHub: [@memo-13-byte](https://github.com/memo-13-byte)

### 🔗 Related Security Projects

- [Classical Cryptography Toolkit](https://github.com/memo-13-byte/classical-cryptography-toolkit) - Cipher implementation & cryptanalysis
- [Secure Flask Auth Portal](https://github.com/memo-13-byte/secure-flask-auth-portal) - 2FA with hash chain OTP
- [Hybrid Kerberos System](https://github.com/memo-13-byte/hybrid-kerberos-system) - Enterprise authentication

---

## 🙏 Acknowledgments

- **Hacettepe University** - Computer Engineering Department
- **BBM 465 Course** - Information Security Laboratory instructors
- **Java Keytool Documentation** - Oracle Java security guides
- **PKI Standards** - X.509 certificate specifications

---

## 📊 Statistics

![Java](https://img.shields.io/badge/Java-100%25-orange?style=flat-square)
![Lines of Code](https://img.shields.io/badge/Lines%20of%20Code-600+-green?style=flat-square)
![Security](https://img.shields.io/badge/Crypto-RSA%202048-blue?style=flat-square)

---

## 📚 References

- [Java Keytool Documentation](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html)
- [javax.crypto Package](https://docs.oracle.com/javase/8/docs/api/javax/crypto/package-summary.html)
- [X.509 Certificate Standard](https://datatracker.ietf.org/doc/html/rfc5280)
- [RSA Cryptography Standard](https://datatracker.ietf.org/doc/html/rfc8017)

---

<div align="center">

**⭐ Star this repository if you found it helpful!**

**Made with ❤️ for enterprise security education**

</div>