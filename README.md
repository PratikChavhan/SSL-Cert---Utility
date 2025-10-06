# 🔐 SSL Certificate & Key Extraction Utility

A **.NET Framework 4.7.2** console utility to extract public and private keys from HTTPS endpoints and `.pfx` files.  
Authored by **PratikChavhan**.

---

## 📁 Project Overview

This is a small CLI tool that exposes three main functions:

1. **Get Public Key from HTTPS host** — Connects to a host (via TCP + TLS) and retrieves the server certificate, then extracts the public key (DER -> Base64).
2. **Export Private Key from PFX** — Loads a `.pfx` file (with password), extracts the RSA private key and exports it in PKCS#8 PEM format.
3. **Get Public Key from PFX** — Reads a `.pfx` file and extracts the public key (DER -> Base64).

The original project layout (as present in Visual Studio) is expected to be:

```
Solution 'SSL Certificate - Utility'
  └─ SSL Certificate - KeysExtraction (Console App)
     ├─ Properties
     ├─ References
     ├─ App.config
     ├─ packages.config
     └─ Program.cs
```

---

## 🧭 Detailed Flow (Architecture)

The diagram is available at **`docs/architecture.png`** (also included in this package). The steps below match the diagram and describe internals in detail:

1. **User Input** — CLI menu accepts either hostname (and optional port) or a path to a `.pfx` file plus password and output path.
2. **Network / Certificate Retrieval** (for HTTPS host):
   - Establish TCP connection to the host:port.
   - Perform TLS handshake using `System.Net.Security.SslStream`.
   - Retrieve the remote certificate bytes via `sslStream.RemoteCertificate`.
3. **Certificate Parsing**:
   - Wrap the certificate bytes in a `X509Certificate2` object (System.Security.Cryptography).
   - Use BouncyCastle (`Org.BouncyCastle.X509.X509CertificateParser`) to parse raw DER bytes into a BouncyCastle `X509Certificate` object.
   - Access `CertificateStructure.SubjectPublicKeyInfo` (a `SubjectPublicKeyInfo` object).
4. **Public Key Extraction & Encoding**:
   - Obtain DER-encoded bytes from `SubjectPublicKeyInfo.GetDerEncoded()`.
   - Convert DER bytes to Base64 (human-readable representation) and display to the user.
5. **Private Key Export (PFX)**:
   - Load `.pfx` into `X509Certificate2` with `X509KeyStorageFlags.Exportable` and `PersistKeySet` to obtain the private key.
   - Cast `cert.PrivateKey` to `RSACryptoServiceProvider` (legacy API used with .NET 4.7.2).
   - Convert the .NET RSA provider to BouncyCastle `AsymmetricCipherKeyPair` using `DotNetUtilities.GetKeyPair(...)`.
   - Use `Org.BouncyCastle.OpenSsl.PemWriter` to write the private key in PKCS#8 PEM format to an output file.
6. **Output** — Write exported PEM file (for private key) or print Base64 DER public key to console.

---

## ⚙️ Requirements & Setup

- **Target framework:** .NET Framework **4.7.2**
- **NuGet packages**:
  - `BouncyCastle` (e.g., `Install-Package BouncyCastle -Version 1.8.10`)

### Build & Run (Visual Studio)

1. Open the solution in Visual Studio (2017/2019 recommended).  
2. Restore NuGet packages.  
3. Build the project.  
4. Run the console application. Follow the interactive menu prompts.

---

## 🚀 Example Usage

**Get public key from HTTPS site**
```
Enter hostname (e.g. example.com): google.com
Enter port (default 443):
```
Output (DER -> Base64):
```
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJ1...
```

**Export private key from PFX**
```
Enter path to PFX file: C:\certs\mycert.pfx
Enter PFX password: ********
Enter output PEM path: C:\keys\private_key.pem
```
Output:
```
✅ Private key exported successfully to: C:\keys\private_key.pem
```

---

## 🔒 Security & Notes

- **Handle private keys carefully.** Do not check private keys into source control. Protect exported files with appropriate filesystem permissions.
- **Legal & ethical:** Only analyze or export keys from certificates you own or have explicit permission to inspect.
- On .NET 4.7.2 `RSACryptoServiceProvider` may be used; consider migrating to `RSA` (Cng/Csp or `RSACng`) and newer APIs if you plan to port to .NET Core/.NET 5+.
- The code uses a permissive server certificate validation when connecting to HTTPS hosts (accepts any cert) — this is to obtain the certificate, not to verify trust. For production tools, implement proper validation.

---

## 🛠️ Files Included

- `Program.cs` — (your existing program; not overwritten)  
- `README.md` — this document.  
- `LICENSE` — MIT license.  
- `docs/architecture.png` — detailed architecture diagram (generated).

---

## 📦 License

This project is provided under the **MIT License**. See `LICENSE` for details.

---

## 👨‍💻 Author

**PratikChavhan** — GitHub: `PratikChavhan`

---
