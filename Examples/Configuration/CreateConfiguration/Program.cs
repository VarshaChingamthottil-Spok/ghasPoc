using ComponentSpace.SAML2.Configuration;
using System;
using System.Collections.Generic;
using System.Xml;

namespace CreateConfiguration
{
    /// <summary>
    /// Creates local identity provider or service provider SAML configuration.
    /// 
    /// Usage: CreateConfiguration.exe
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var samlConfiguration = new SAMLConfiguration();

                switch (GetProviderType().ToLower())
                {
                    case "idp":
                        samlConfiguration.LocalIdentityProviderConfiguration = CreateIdentityProviderConfiguration();
                        break;

                    case "sp":
                        samlConfiguration.LocalServiceProviderConfiguration = CreateServiceProviderConfiguration();
                        break;

                    default:
                        throw new ArgumentException("The provider type must either be \"IdP\" or \"SP\".");
                }

                SaveConfiguration(samlConfiguration);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static string GetProviderType()
        {
            Console.Write("SAML provider type (IdP | SP): ");
            var providerType = Console.ReadLine();

            if (string.IsNullOrEmpty(providerType))
            {
                throw new ArgumentException("A provider type must be specified.");
            }

            return providerType;
        }

        private static LocalIdentityProviderConfiguration CreateIdentityProviderConfiguration()
        {
            var localIdentityProviderConfiguration = new LocalIdentityProviderConfiguration()
            {
                Name = GetProviderName()
            };

            Console.Write("Single Sign-On Service URL [None]: ");
            localIdentityProviderConfiguration.SingleSignOnServiceUrl = ReadLine();

            Console.Write("Single Logout Service URL [None]: ");
            localIdentityProviderConfiguration.SingleLogoutServiceUrl = ReadLine();

            GetCertificateConfiguration(localIdentityProviderConfiguration);

            return localIdentityProviderConfiguration;
        }

        private static LocalServiceProviderConfiguration CreateServiceProviderConfiguration()
        {
            var localServiceProviderConfiguration = new LocalServiceProviderConfiguration()
            {
                Name = GetProviderName()
            };

            Console.Write("Assertion Consumer Service URL [None]: ");
            localServiceProviderConfiguration.AssertionConsumerServiceUrl = ReadLine();

            Console.Write("Single Logout Service URL [None]: ");
            localServiceProviderConfiguration.SingleLogoutServiceUrl = ReadLine();

            GetCertificateConfiguration(localServiceProviderConfiguration);

            return localServiceProviderConfiguration;
        }

        private static string GetProviderName()
        {
            Console.Write("Name: ");
            var name = ReadLine();

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A provider name must be specified.");
            }

            return name;
        }

        private static void GetCertificateConfiguration(LocalProviderConfiguration localProviderConfiguration)
        {
            Console.Write("X.509 certificate PFX file [None]: ");
            var fileName = "Spok.pfx";

            if (string.IsNullOrEmpty(fileName))
            {
                return;
            }

            Console.Write("X.509 certificate PFX password [None]: ");
            var password = "Director5";

            localProviderConfiguration.LocalCertificates = new List<CertificateConfiguration>()
            {
                new CertificateConfiguration()
                {
                    FileName = fileName,
                    Password = password
                }
            };
        }

        private static void SaveConfiguration(SAMLConfiguration samlConfiguration)
        {
            Console.Write("SAML configuration file [saml.config]: ");

            var fileName = "Spoksaml.config";

            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "saml.config";
            }

            using (XmlTextWriter xmlTextWriter = new XmlTextWriter(fileName, null))
            {
                xmlTextWriter.Formatting = Formatting.Indented;
                samlConfiguration.ToXml().OwnerDocument.Save(xmlTextWriter);
            }
        }

        private static string ReadLine()
        {
            var line = Console.ReadLine();

            if (string.IsNullOrEmpty(line))
            {
                line = null;
            }

            return line;
        }
    }
}
