using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Configuration;
using ComponentSpace.SAML2.Metadata;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace CreateMetadata
{
    /// <summary>
    /// Creates local identity provider or service provider SAML metadata for distribution to a partner provider.
    /// 
    /// Usage: CreateMetadata.exe
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                EntityDescriptor entityDescriptor = null;

                switch (GetProviderType().ToLower())
                {
                    case "idp":
                        entityDescriptor = CreateIdentityProviderMetadata();
                        break;

                    case "sp":
                        entityDescriptor = CreateServiceProviderMetadata();
                        break;

                    default:
                        throw new ArgumentException("The provider type must either be \"IdP\" or \"SP\".");
                }

                SaveMetadata(entityDescriptor);
            }

            catch (Exception exception)
            {
                Console.WriteLine(exception.ToString());
            }
        }

        private static EntityDescriptor CreateIdentityProviderMetadata()
        {
            var entityID = GetEntityID();

            Console.Write("X.509 signature certificate .CER file [None]: ");
            var fileName = Console.ReadLine();
            var signatureCertificate = LoadCertificate(fileName);

            Console.Write("Single Sign-On Service URL: ");
            var singleSignOnServiceUrl = Console.ReadLine();

            if (string.IsNullOrEmpty(singleSignOnServiceUrl))
            {
                throw new ArgumentException("A single sign-on service URL must be specified.");
            }

            Console.Write("Single Logout Service URL [None]: ");
            var singleLogoutServiceUrl = Console.ReadLine();

            Console.Write("Name ID Format [None]: ");
            var nameIDFormat = Console.ReadLine();

            var wantAuthnRequestsSigned = GetBoolean("Want authn requests signed? [True]: ");

            var localIdentityProviderConfiguration = new LocalIdentityProviderConfiguration()
            {
                Name = entityID
            };

            var partnerServiceProviderConfiguration = new PartnerServiceProviderConfiguration()
            {
                NameIDFormat = !string.IsNullOrEmpty(nameIDFormat) ? nameIDFormat : SAMLIdentifiers.NameIdentifierFormats.Unspecified,
                WantAuthnRequestSigned = wantAuthnRequestsSigned.HasValue ? wantAuthnRequestsSigned.Value : true
            };

            return MetadataExporter.Export(localIdentityProviderConfiguration, signatureCertificate, singleSignOnServiceUrl, singleLogoutServiceUrl, partnerServiceProviderConfiguration);
        }

        private static EntityDescriptor CreateServiceProviderMetadata()
        {
            var entityID = GetEntityID();

            Console.Write("X.509 signature certificate .CER file [None]: ");
            //var fileName = Console.ReadLine();
            var fileName = "C:\\_Varsha\\SAMLv20-evaluation\\SAML for .NET\\Examples\\SSO\\WebForms\\ExampleServiceProvider\\Certificates\\sp.cer";
            var signatureCertificate = LoadCertificate(fileName);

            Console.Write("X.509 encryption certificate .CER file [None]: ");
            //fileName = Console.ReadLine();
            fileName = "C:\\_Varsha\\SAMLv20-evaluation\\SAML for .NET\\Examples\\SSO\\WebForms\\ExampleServiceProvider\\Certificates\\sp.cer";//Console.ReadLine();
            var encryptionCertificate = LoadCertificate(fileName);

            Console.Write("Assertion Consumer Service URL: ");
            var assertionConsumerServiceUrl = "https:\\\\mcdevenv:444\\SAML\\AssertionConsumerService.aspx";//Console.ReadLine();

            if (string.IsNullOrEmpty(assertionConsumerServiceUrl))
            {
                throw new ArgumentException("An assertion consumer service URL must be specified.");
            }

            Console.Write("Single Logout Service URL [None]: ");
            var singleLogoutServiceUrl = "https:\\\\mcdevenv:444\\SAML\\SLOService.aspx";// Console.ReadLine();

            Console.Write("Name ID Format [None]: ");
            var nameIDFormat = Console.ReadLine();

            var authnRequestsSigned = GetBoolean("Authn requests signed? [True]: ");
            var wantAssertionsSigned = GetBoolean("Want assertions signed? [True]: ");

            var localServiceProviderConfiguration = new LocalServiceProviderConfiguration()
            {
                Name = entityID
            };

            var partnerIdentityProviderConfiguration = new PartnerIdentityProviderConfiguration()
            {
                NameIDFormat = !string.IsNullOrEmpty(nameIDFormat) ? nameIDFormat : SAMLIdentifiers.NameIdentifierFormats.Unspecified,
                SignAuthnRequest = authnRequestsSigned.HasValue ? authnRequestsSigned.Value : true,
                WantAssertionSigned = wantAssertionsSigned.HasValue ? wantAssertionsSigned.Value : true
            };

            return MetadataExporter.Export(localServiceProviderConfiguration, signatureCertificate, encryptionCertificate, assertionConsumerServiceUrl, singleLogoutServiceUrl, partnerIdentityProviderConfiguration);
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

        private static string GetEntityID()
        {
            Console.Write("Entity ID: ");
            var entityID = Console.ReadLine();

            if (string.IsNullOrEmpty(entityID))
            {
                throw new ArgumentException("An entity ID must be specified.");
            }

            return entityID;
        }

        private static bool? GetBoolean(string prompt)
        {
            bool? booleanValue = null;

            Console.Write(prompt);
            var inputText = Console.ReadLine();

            if (!string.IsNullOrEmpty(inputText))
            {
                try
                {
                    booleanValue = Boolean.Parse(inputText);
                }

                catch (Exception exception)
                {
                    throw new ArgumentException("A boolean value is required.", exception);
                }
            }

            return booleanValue;
        }

        private static X509Certificate2 LoadCertificate(string fileName)
        {
            if (string.IsNullOrEmpty(fileName))
            {
                return null;
            }

            if (!File.Exists(fileName))
            {
                throw new ArgumentException(string.Format("The X.509 certificate file {0} doesn't exist.", fileName));
            }

            return new X509Certificate2(fileName);
        }

        private static void SaveMetadata(EntityDescriptor entityDescriptor)
        {
            Console.Write("SAML metadata file [saml-metadata.xml]: ");

            var fileName = "C:\\_Varsha\\SAMLv20-evaluation\\SAML for .NET\\Examples\\SSO\\WebForms\\ExampleServiceProvider\\Certificates\\ExampleServiceProvidersaml-metadata.xml";//Console.ReadLine();

            if (string.IsNullOrEmpty(fileName))
            {
                fileName = "saml-metadata.xml";
            }

            using (XmlTextWriter xmlTextWriter = new XmlTextWriter(fileName, null))
            {
                xmlTextWriter.Formatting = System.Xml.Formatting.Indented;
                entityDescriptor.ToXml().OwnerDocument.Save(xmlTextWriter);
            }
        }
    }
}
