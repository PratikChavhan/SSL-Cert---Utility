using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;

namespace SSL_Certificate___KeysExtraction
{
	class Program
	{
		static void Main()
		{
			while (true)
			{
				Console.WriteLine("\n===== MENU =====");
				Console.WriteLine("1 -> Get Public Key from HTTPS site");
				Console.WriteLine("2 -> Export Private Key from PFX");
				Console.WriteLine("3 -> Get Public Key from PFX");
				Console.WriteLine("N -> Stop");
				Console.Write("Enter choice: ");

				string choice = Console.ReadLine()?.Trim().ToUpperInvariant();

				switch (choice)
				{
					case "1":
						getPublicKeyFromHost();
						break;

					case "2":
						exportPrivateKeyFromPfx();
						break;

					case "3":
						getPublicKeyFromPfx();
						break;


                    case "4":
                        getPublicKeyFromPrivateKey();
                        break;

                    case "N":
						Console.WriteLine("Stopping...");
						return;

					default:
						Console.WriteLine("⚠️ Invalid choice. Please enter 1, 2, 3, or N.");
						break;
				}

				Console.WriteLine(); // newline before next menu
			}
		}

		// ✅ Option 1 - Extract public key from HTTPS host
		public static void getPublicKeyFromHost()
		{
			Console.Write("Enter hostname (e.g. example.com): ");
			string host = Console.ReadLine()?.Trim();

			if (string.IsNullOrWhiteSpace(host))
			{
				Console.WriteLine("❌ Hostname cannot be empty.");
				return;
			}

			Console.Write("Enter port (default 443): ");
			string portInput = Console.ReadLine();
			int port = 443;
			if (!string.IsNullOrWhiteSpace(portInput) &&
				(!int.TryParse(portInput, out port) || port <= 0 || port > 65535))
			{
				Console.WriteLine("⚠️ Invalid port entered. Using default 443.");
				port = 443;
			}

			try
			{
				using (var client = new TcpClient(host, port))
				using (var sslStream = new SslStream(client.GetStream(), false, (a, b, c, d) => true))
				{
					sslStream.AuthenticateAsClient(host);
					var cert = new X509Certificate2(sslStream.RemoteCertificate);

					var parser = new X509CertificateParser();
					var bcCert = parser.ReadCertificate(cert.RawData);

					SubjectPublicKeyInfo spki = bcCert.CertificateStructure.SubjectPublicKeyInfo;
					byte[] derBytes = spki.GetDerEncoded();
					string base64Key = Convert.ToBase64String(derBytes);

					Console.WriteLine("\n===== RSA Public Key (DER -> Base64) =====");
					Console.WriteLine(base64Key);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine("❌ Error: " + ex.Message);
			}
		}

		// ✅ Option 2 - Export private key from PFX (PKCS#8)
		public static void exportPrivateKeyFromPfx()
		{
			Console.Write("Enter path to PFX file: ");
			string pfxPath = Console.ReadLine();

			if (string.IsNullOrWhiteSpace(pfxPath) || !File.Exists(pfxPath))
			{
				Console.WriteLine("❌ Invalid PFX path.");
				return;
			}

			Console.Write("Enter PFX password: ");
			string pfxPassword = ReadPassword();

			Console.Write("Enter output PEM path (e.g. C:\\private_key_pkcs8.pem): ");
			string outPemPath = Console.ReadLine();

			try
			{
				var cert = new X509Certificate2(pfxPath, pfxPassword,
					X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

				if (!cert.HasPrivateKey)
				{
					Console.WriteLine("❌ No private key found in the PFX.");
					return;
				}

				var rsa = cert.PrivateKey as RSACryptoServiceProvider;
				if (rsa == null)
				{
					Console.WriteLine("❌ RSA private key not found or not supported.");
					return;
				}

				AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(rsa);

				using (var sw = new StreamWriter(outPemPath))
				{
					var pemWriter = new PemWriter(sw);
					pemWriter.WriteObject(keyPair.Private); // PKCS#8 PRIVATE KEY
				}

				Console.WriteLine("\n✅ Private key exported successfully to:");
				Console.WriteLine(outPemPath);
			}
			catch (Exception ex)
			{
				Console.WriteLine("❌ Error: " + ex.Message);
			}
		}

		// ✅ Option 3 - Extract public key from PFX (same as HTTPS one)
		public static void getPublicKeyFromPfx()
		{
			Console.Write("Enter path to PFX file: ");
			string pfxPath = Console.ReadLine();

			if (string.IsNullOrWhiteSpace(pfxPath) || !File.Exists(pfxPath))
			{
				Console.WriteLine("❌ Invalid PFX path.");
				return;
			}

			Console.Write("Enter PFX password: ");
			string pfxPassword = ReadPassword();

			try
			{
				var cert = new X509Certificate2(pfxPath, pfxPassword,
					X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

				var parser = new X509CertificateParser();
				var bcCert = parser.ReadCertificate(cert.RawData);

				SubjectPublicKeyInfo spki = bcCert.CertificateStructure.SubjectPublicKeyInfo;
				byte[] derBytes = spki.GetDerEncoded();
				string base64Key = Convert.ToBase64String(derBytes);

				Console.WriteLine("\n===== RSA Public Key from PFX (DER -> Base64) =====");
				Console.WriteLine(base64Key);
			}
			catch (Exception ex)
			{
				Console.WriteLine("❌ Error: " + ex.Message);
			}
		}

        public static void getPublicKeyFromPrivateKey()
        {
            Console.Write("Enter path to Private key file: ");
            string privateKeyPath = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
            {
                Console.WriteLine("❌ Invalid Private Key path.");
                return;
            }

            try
            {
                AsymmetricKeyParameter privateKey;

                using (TextReader reader = File.OpenText(privateKeyPath))
                {
                    PemReader pemReader = new PemReader(reader);
                    privateKey = (AsymmetricKeyParameter)pemReader.ReadObject();
                }

                // Convert to RSA parameters
                RsaPrivateCrtKeyParameters rsaPrivate =
                    (RsaPrivateCrtKeyParameters)privateKey;

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(rsaPrivate);

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaParams);

                    // Export PUBLIC KEY
                    RSAParameters publicParams = rsa.ExportParameters(false);

                    string publicKeyBase64 = Convert.ToBase64String(publicParams.Modulus);

                    Console.WriteLine("===== RSA Public Key (Base64 Modulus) =====");
                    Console.WriteLine(publicKeyBase64);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("❌ Error: " + ex.Message);
            }
        }


        // Reads password from console without echo
        private static string ReadPassword()
		{
			string password = string.Empty;
			ConsoleKeyInfo key;

			do
			{
				key = Console.ReadKey(intercept: true);
				if (key.Key == ConsoleKey.Enter)
					break;
				if (key.Key == ConsoleKey.Backspace && password.Length > 0)
				{
					password = password.Substring(0, password.Length - 1);
					Console.Write("\b \b");
				}
				else if (!char.IsControl(key.KeyChar))
				{
					password += key.KeyChar;
					Console.Write("*");
				}
			} while (true);

			Console.WriteLine();
			return password;
		}
        //Test Commit
	}
}
