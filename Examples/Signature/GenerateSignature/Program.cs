using System;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;

using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Protocols;
using ComponentSpace.SAML2.Metadata;
using ComponentSpace.SAML2.Utility;

namespace GenerateSignature
{
    /// <summary>
    /// Signs SAML v2.0 assertions, requests, responses and metadata using XML digital signatures.
    /// 
    /// Usage: GenerateSignature [-d <digestAlgorithm>] [-s <signatureAlgorithm>] -c <certificateFileName> -p <password> <filename>
    /// 
    /// where the file contains a SAML assertion, request, response or metadata,
    /// the digest method defaults to http://www.w3.org/2001/04/xmlenc#sha256
    /// and the signature method defaults to http://www.w3.org/2001/04/xmldsig-more#rsa-sha256.
    /// 
    /// The signed SAML is written to standard output.
    /// </summary>
    static class Program
    {
        private static string digestMethod = SAMLIdentifiers.DigestMethods.SHA256;
        private static string signatureMethod = SAMLIdentifiers.SignatureMethods.RSA_SHA256;
        private static string certificateFileName;
        private static string password;
        private static string fileName;

        private static X509Certificate2 x509Certificate;

        private static void ParseArguments(String[] args)
        {
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("-"))
                {
                    switch (args[i].Substring(1))
                    {
                        case "d":
                            if (++i < args.Length)
                            {
                                digestMethod = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing digest method.");
                            }
                            break;

                        case "s":
                            if (++i < args.Length)
                            {
                                signatureMethod = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing signature method.");
                            }
                            break;

                        case "c":
                            if (++i < args.Length)
                            {
                                certificateFileName = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing certificate file.");
                            }
                            break;


                        case "p":
                            if (++i < args.Length)
                            {
                                password = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing password.");
                            }
                            break;
                        default:
                            throw new ArgumentException("Unsupported option.");
                    }
                }
                else
                {
                    fileName = args[i];
                }
            }

            if (string.IsNullOrEmpty(certificateFileName))
            {
                throw new ArgumentException("Missing certificate file.");
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Missing password.");
            }

            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentException("Missing file.");
            }
        }

        private static void ShowUsage()
        {
            Console.Error.WriteLine("Usage: GenerateSignature [-d <digestAlgorithm>] [-s <signatureAlgorithm>] -c <certificateFileName> -p <password> <filename>");
        }

        private static void LoadKeyAndCertificate()
        {
            Console.Error.WriteLine("Loading certificate and key from " + certificateFileName);

            if (!File.Exists(certificateFileName))
            {
                throw new ArgumentException("The certificate file " + certificateFileName + " doesn't exist.");
            }

            x509Certificate = new X509Certificate2(certificateFileName, password);
        }

        private static XmlDocument LoadXmlDocument()
        {
            Console.Error.WriteLine("Loading " + fileName);

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(fileName);

            return xmlDocument;
        }

        private static void SignAssertion(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Signing SAML assertion");
            SAMLAssertionSignature.Generate(xmlElement, CertificateHelper.GetPrivateKey(x509Certificate), x509Certificate, null, digestMethod, signatureMethod);

            if (!SAMLAssertionSignature.Verify(xmlElement))
            {
                Console.Error.WriteLine("The SAML assertion signature failed to verify.");
            }
        }

        private static void SignMessage(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Signing SAML message");
            SAMLMessageSignature.Generate(xmlElement, CertificateHelper.GetPrivateKey(x509Certificate), x509Certificate, null, digestMethod, signatureMethod);

            if (!SAMLMessageSignature.Verify(xmlElement))
            {
                Console.Error.WriteLine("The SAML message signature failed to verify.");
            }
        }

        private static void SignMetadata(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Signing SAML metadata");
            SAMLMetadataSignature.Generate(xmlElement, CertificateHelper.GetPrivateKey(x509Certificate), x509Certificate, null, digestMethod, signatureMethod);

            if (!SAMLMetadataSignature.Verify(xmlElement))
            {
                Console.Error.WriteLine("The SAML metadata signature failed to verify.");
            }
        }

        static void Main(string[] args)
        {
            try
            {
                ParseArguments(args);
                LoadKeyAndCertificate();

                XmlDocument xmlDocument = LoadXmlDocument();

                switch (xmlDocument.DocumentElement.NamespaceURI)
                {
                    case SAML.NamespaceURIs.Assertion:
                        SignAssertion(xmlDocument.DocumentElement);
                        break;

                    case SAML.NamespaceURIs.Protocol:
                        SignMessage(xmlDocument.DocumentElement);
                        break;

                    case SAML.NamespaceURIs.Metadata:
                        SignMetadata(xmlDocument.DocumentElement);
                        break;

                    default:
                        throw new ArgumentException("Unexpected namespace URI " + xmlDocument.DocumentElement.NamespaceURI);
                }

                Console.WriteLine(xmlDocument.OuterXml);
            }

            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.ToString());

                if (exception is ArgumentException)
                {
                    ShowUsage();
                }
            }
        }
    }
}
