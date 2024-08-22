using ComponentSpace.SAML2.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace SetupSAML
{
    /// <summary>
    /// Sets up the local identity provider or service provider SAML configuration including:
    /// 
    /// - Creating the local provider's certificate
    /// - Creating the local provider's SAML configuration
    /// - Generating SAML metadata for the local provider
    /// - Updating the SAML configuration with the partner provider's SAML metadata
    /// 
    /// Usage: SetupSAML.exe
    /// </summary>
    internal class Program
    {
        private const string certificateDirectory = "Certificates";

        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("An identity provider (IdP) authenticates users. A service provider (SP) automatically logs users in.");
                Console.Write("Is your application an IdP or SP (IdP | SP): ");

                if (!Enum.TryParse(Console.ReadLine(), out ProviderType providerType))
                {
                    throw new ArgumentException("The application type must be IdP or SP.");
                }

                Console.WriteLine();
                Console.WriteLine($"The application's URL is used as the name of your {providerType}.");
                Console.Write("Application URL (eg https://myapp.com): ");

                var applicationUrl = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(applicationUrl))
                {
                    throw new ArgumentException("The application URL is missing.");
                }

                var samlConfiguration = new SAMLConfiguration();

                if (providerType == ProviderType.IdP)
                {
                    ConfigureIdentityProvider(samlConfiguration, applicationUrl);

                    ImportPartnerServiceProviderMetadata(samlConfiguration);
                }
                else
                {
                    ConfigureServiceProvider(samlConfiguration, applicationUrl);

                    ImportPartnerIdentityProviderMetadata(samlConfiguration);
                }

                SaveConfiguration(samlConfiguration);

                ExportMetadata(samlConfiguration);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static void ConfigureIdentityProvider(SAMLConfiguration samlConfiguration, string applicationUrl)
        {
            var singleSignOnServiceUrl = GetSingleSignOnServiceUrl(applicationUrl);
            var singleLogoutServiceUrl = GetSingleLogoutServiceUrl(applicationUrl);

            var (cerFileName, pfxFileName, pfxPassword) = CreateSelfSignedCertificate(applicationUrl);

            samlConfiguration.LocalIdentityProviderConfiguration = new LocalIdentityProviderConfiguration()
            {
                Name = applicationUrl,
                SingleSignOnServiceUrl = singleSignOnServiceUrl,
                SingleLogoutServiceUrl = singleLogoutServiceUrl,
                LocalCertificates = new List<CertificateConfiguration>
                {
                    new CertificateConfiguration
                    {
                        FileName = pfxFileName,
                        Password= pfxPassword
                    }
                }
            };
        }

        private static void ConfigureServiceProvider(SAMLConfiguration samlConfiguration, string applicationUrl)
        {
            var assertionConsumerServiceUrl = GetAssertionConsumerServiceUrl(applicationUrl);
            var singleLogoutServiceUrl = GetSingleLogoutServiceUrl(applicationUrl);

            var (cerFileName, pfxFileName, pfxPassword) = CreateSelfSignedCertificate(applicationUrl);

            samlConfiguration.LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
            {
                Name = applicationUrl,
                AssertionConsumerServiceUrl = assertionConsumerServiceUrl,
                SingleLogoutServiceUrl = singleLogoutServiceUrl,
                LocalCertificates = new List<CertificateConfiguration>
                {
                    new CertificateConfiguration
                    {
                        FileName = pfxFileName,
                        Password= pfxPassword
                    }
                }
            };
        }

        private static string GetSingleSignOnServiceUrl(string applicationUrl)
        {
            var signOnUrl = AppendUrl(applicationUrl, "/saml/singlesignonservice");

            Console.WriteLine();
            Console.WriteLine($"The single sign-on service (SSO) URL is where SAML authn requests are received.");
            Console.Write($"Sign-on URL [{signOnUrl}]: ");

            var url = Console.ReadLine();

            if (!string.IsNullOrWhiteSpace(url))
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                {
                    throw new ArgumentException($"The URL {url} is invalid.");
                }

                signOnUrl = url;
            }

            return signOnUrl;
        }

        private static string GetSingleLogoutServiceUrl(string applicationUrl)
        {
            var logoutUrl = AppendUrl(applicationUrl, "/saml/singlelogoutservice");

            Console.WriteLine();
            Console.WriteLine($"The single logout service (SLO) URL is where SAML logout messages are received.");
            Console.Write($"Logout URL [{logoutUrl}]: ");

            var url = Console.ReadLine();

            if (!string.IsNullOrWhiteSpace(url))
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                {
                    throw new ArgumentException($"The URL {url} is invalid.");
                }

                logoutUrl = url;
            }

            return logoutUrl;
        }

        private static string GetAssertionConsumerServiceUrl(string applicationUrl)
        {
            var acsUrl = AppendUrl(applicationUrl, "/saml/assertionconsumerservice");

            Console.WriteLine();
            Console.WriteLine($"The assertion consumer service (ACS) URL is where SAML assertions are received.");
            Console.Write($"ACS URL [{acsUrl}]: ");

            var url = Console.ReadLine();

            if (!string.IsNullOrWhiteSpace(url))
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out _))
                {
                    throw new ArgumentException($"The URL {url} is invalid.");
                }

                acsUrl = url;
            }

            return acsUrl;
        }

        private static string AppendUrl(string baseUrl, string relativeUrl)
        {
            var stringBuilder = new StringBuilder();

            stringBuilder.Append(baseUrl);

            if (!(baseUrl.EndsWith("/") || relativeUrl.StartsWith("/")))
            {
                stringBuilder.Append('/');
            }

            stringBuilder.Append(relativeUrl);

            return stringBuilder.ToString();
        }

        private static (string cerFileName, string pfxFileName, string pfxPassword) CreateSelfSignedCertificate(string applicationUrl)
        {
            const string certificateDirectory = "Certificates";
            const int keySizeInBits = 2048;
            const int yearsBeforeExpiring = 5;

            var subjectAlternativeName = new Uri(applicationUrl).Authority;
            var subjectName = $"CN={subjectAlternativeName}";

            using (var privateKey = RSA.Create(keySizeInBits))
            {
                var certificateRequest = new CertificateRequest(subjectName, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, false));

                var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();

                subjectAlternativeNameBuilder.AddDnsName(subjectAlternativeName);
                certificateRequest.CertificateExtensions.Add(subjectAlternativeNameBuilder.Build());

                var notBefore = DateTimeOffset.UtcNow;
                var notAfter = notBefore.AddYears(yearsBeforeExpiring);

                using (var x509Certificate = certificateRequest.CreateSelfSigned(notBefore, notAfter))
                {
                    Directory.CreateDirectory(certificateDirectory);

                    var fileNameWithoutExtension = Regex.Replace(subjectAlternativeName, "[^A-Za-z0-9 .]", "-");

                    var cerFileName = $"{certificateDirectory}\\{fileNameWithoutExtension}.cer";

                    var stringBuilder = new StringBuilder();

                    stringBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
                    stringBuilder.AppendLine(Convert.ToBase64String(x509Certificate.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                    stringBuilder.AppendLine("-----END CERTIFICATE-----");

                    File.WriteAllText(cerFileName, stringBuilder.ToString());

                    var pfxFileName = $"{certificateDirectory}\\{fileNameWithoutExtension}.pfx";
                    var pfxPassword = Guid.NewGuid().ToString();

                    File.WriteAllBytes(pfxFileName, x509Certificate.Export(X509ContentType.Pfx, pfxPassword));

                    return (cerFileName, pfxFileName, pfxPassword);
                }
            }
        }

        private static void ImportPartnerIdentityProviderMetadata(SAMLConfiguration samlConfiguration)
        {
            ImportMetadata(ProviderType.IdP, samlConfiguration);
        }

        private static void ImportPartnerServiceProviderMetadata(SAMLConfiguration samlConfiguration)
        {
            ImportMetadata(ProviderType.SP, samlConfiguration);
        }

        private static void SaveConfiguration(SAMLConfiguration samlConfiguration)
        {
            const string configurationFileName = "saml.config";

            XmlDocument xmlDocument = samlConfiguration.ToXml().OwnerDocument;

            using (XmlTextWriter xmlTextWriter = new XmlTextWriter(configurationFileName, null))
            {
                xmlTextWriter.Formatting = Formatting.Indented;
                xmlDocument.Save(xmlTextWriter);
            }

            Console.WriteLine();
            Console.WriteLine($"The configuration has been saved to {configurationFileName}.");
        }

        private static void ImportMetadata(ProviderType partnerProviderType, SAMLConfiguration samlConfiguration)
        {
            Console.WriteLine();
            Console.WriteLine($"Optionally import the partner {partnerProviderType} SAML metadata.");
            Console.Write("SAML metadata file to import [None]: ");

            var metadataLocation = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(metadataLocation))
            {
                return;
            }

            MetadataImporter.ImportFile(metadataLocation, samlConfiguration, certificateDirectory);
        }

        private static void ExportMetadata(SAMLConfiguration samlConfiguration)
        {
            const string metadataFileName = "saml-metadata.xml";

            var entityDescriptor = MetadataExporter.Export(samlConfiguration);

            using (var xmlTextWriter = new XmlTextWriter(metadataFileName, null))
            {
                xmlTextWriter.Formatting = Formatting.Indented;

                entityDescriptor.ToXml().OwnerDocument.Save(xmlTextWriter);
            };

            Console.WriteLine($"The SAML metadata has been saved to {metadataFileName}.");
        }

        enum ProviderType
        {
            IdP,
            SP
        }
    }
}
