using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CreateSelfSignedCert
{
    /// <summary>
    /// Creates a self-signed X.509 certificate.
    /// 
    /// For maximum compatibility, the "Microsoft Enhanced RSA and AES Cryptographic Provider" cryptographic service provider (CSP)
    /// is used to create the private key. This is supported in all versions of the .NET framework.
    /// 
    /// The alternative of a Cryptography API: Next Generation (CNG) provider such as the default
    /// "Microsoft Software Key Storage Provider" requires .NET framework v4.6 or higher.
    /// 
    /// Attempting to use a CNG provider private key in earlier versions of the .NET framework results in a 
    /// "CryptographicException: Invalid provider type specified".
    /// 
    /// Usage: CreateSelfSignedCert.exe
    /// </summary>
    class Program
    {
        private const int providerType = 24;
        private const string providerName = "Microsoft Enhanced RSA and AES Cryptographic Provider";

        static void Main(string[] args)
        {
            try
            {
                Console.Write("Subject distinguished name (eg CN=test): ");
                var subjectName = "CN=Spok";

                if (string.IsNullOrEmpty(subjectName))
                {
                    throw new ArgumentException("A subject distinguished name must be specified.");
                }

                try
                {
                    new X500DistinguishedName(subjectName);
                }

                catch (Exception exception)
                {
                    throw new ArgumentException("The subject must be an X.500 distinguished name (eg CN=test).", exception);
                }

                Console.Write("Optional subject alternative name (eg test): ");
                var subjectAlternativeName = "Spok";

                var keySizeInBits = 2048;
                Console.Write($"Key Size in bits [{keySizeInBits}]: ");
                var input = "2048";

                if (!string.IsNullOrEmpty(input) && !int.TryParse(input, out keySizeInBits))
                {
                    throw new ArgumentException("The key size must be an integer.");
                }

                var yearsBeforeExpiring = 5;
                Console.Write($"Number of years before expiring [{yearsBeforeExpiring}]: ");
                input = "5";

                if (!string.IsNullOrEmpty(input) && !int.TryParse(input, out yearsBeforeExpiring))
                {
                    throw new ArgumentException("The number of years must be an integer.");
                }

                using (var privateKey = new RSACryptoServiceProvider(keySizeInBits, new CspParameters(providerType, providerName, Guid.NewGuid().ToString())))
                {
                    var certificateRequest = new CertificateRequest(subjectName, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    certificateRequest.CertificateExtensions.Add(
                        new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, false));

                    if (!string.IsNullOrEmpty(subjectAlternativeName))
                    {
                        var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();

                        subjectAlternativeNameBuilder.AddDnsName(subjectAlternativeName);
                        certificateRequest.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());
                    }

                    var notBefore = DateTimeOffset.UtcNow;
                    var notAfter = notBefore.AddYears(yearsBeforeExpiring);

                    using (var x509Certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter))
                    {
                        Console.Write("Certificate file name (eg test.cer): ");
                        var fileName = "Spok.cer";

                        if (string.IsNullOrEmpty(fileName))
                        {
                            throw new ArgumentException("A file name must be specified.");
                        }

                        var stringBuilder = new StringBuilder();

                        stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
                        stringBuilder.AppendLine(Convert.ToBase64String(x509Certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                        stringBuilder.AppendLine("-----END CERTIFICATE-----");

                        File.WriteAllText(fileName, stringBuilder.ToString());
                        Console.WriteLine($"The certificate has been saved to {fileName}.");

                        Console.Write("Private key file name (eg test.pfx): ");
                        fileName = "Spok.pfx";

                        if (string.IsNullOrEmpty(fileName))
                        {
                            throw new ArgumentException("A file name must be specified.");
                        }

                        Console.Write("Private key password: ");
                        var password = "Director5";

                        if (string.IsNullOrEmpty(password))
                        {
                            throw new ArgumentException("A password must be specified.");
                        }

                        File.WriteAllBytes(fileName, x509Certificate.Export(X509ContentType.Pfx, password));
                        Console.WriteLine($"The private key has been saved to {fileName}.");
                    }
                }
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }
    }
}
