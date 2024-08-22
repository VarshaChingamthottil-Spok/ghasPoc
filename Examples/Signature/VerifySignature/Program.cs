using System;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;

using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Protocols;
using ComponentSpace.SAML2.Metadata;
using ComponentSpace.SAML2.Utility;

namespace VerifySignature
{
    /// <summary>
    /// Verifies XML digital signatures on SAML v2.0 assertions, requests, responses and metadata.
    /// 
    /// Usage: VerifySignature [-c <certificateFileName>] <filename>
    /// 
    /// where the file contains a SAML assertion, request, response or metadata.
    /// </summary>
    static class Program
    {
        private static string certificateFileName;
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

                        default:
                            throw new ArgumentException("Unsupported option.");
                    }
                }
                else
                {
                    fileName = args[i];
                }
            }

            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentException("Missing file.");
            }
        }

        private static void ShowUsage()
        {
            Console.Error.WriteLine("VerifySignature [-c <certificateFileName>] <filename>");
        }

        private static void LoadCertificate()
        {
            if (certificateFileName != null)
            {
                Console.Error.WriteLine("Loading certificate " + certificateFileName);

                if (!File.Exists(certificateFileName))
                {
                    throw new ArgumentException("The certificate file " + certificateFileName + " doesn't exist.");
                }

                x509Certificate = new X509Certificate2(certificateFileName);
            }
        }

        private static XmlDocument LoadXmlDocument()
        {
            Console.Error.WriteLine("Loading " + fileName);

            XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
            xmlReaderSettings.DtdProcessing = DtdProcessing.Ignore;
            xmlReaderSettings.XmlResolver = null;

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.XmlResolver = null;

            using (XmlReader xmlReader = XmlReader.Create(new StreamReader(fileName), xmlReaderSettings))
            {
                xmlDocument.Load(xmlReader);
            }

            return xmlDocument;
        }

        private static void VerifyAssertion(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Verifying SAML assertion");

            try
            {
                if (SAMLAssertionSignature.IsSigned(xmlElement))
                {
                    bool verified = SAMLAssertionSignature.Verify(xmlElement, x509Certificate);
                    Console.Error.WriteLine("Verified: " + verified);
                }
                else
                {
                    Console.Error.WriteLine("The SAML assertion isn't signed");
                }
            }

            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.ToString());
            }
        }

        private static void VerifyMessage(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Verifying SAML message");

            try
            {
                if (SAMLMessageSignature.IsSigned(xmlElement))
                {
                    bool verified = SAMLMessageSignature.Verify(xmlElement, x509Certificate);
                    Console.Error.WriteLine("Verified: " + verified);
                }
                else
                {
                    Console.Error.WriteLine("The SAML message isn't signed");
                }
            }

            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.ToString());
            }

            foreach (XmlElement assertionElement in SAMLAssertion.Find(xmlElement))
            {
                VerifyAssertion(assertionElement);
            }
        }

        private static void VerifyMetadata(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Verifying SAML metadata");

            try
            {
                if (SAMLMetadataSignature.IsSigned(xmlElement))
                {
                    bool verified = SAMLMetadataSignature.Verify(xmlElement, x509Certificate);
                    Console.Error.WriteLine("Verified: " + verified);
                }
                else
                {
                    Console.Error.WriteLine("The SAML metadata isn't signed");
                }
            }

            catch (Exception exception)
            {
                Console.Error.WriteLine(exception.ToString());
            }
        }

        static void Main(string[] args)
        {
            try
            {
                ParseArguments(args);
                LoadCertificate();

                XmlDocument xmlDocument = LoadXmlDocument();

                switch (xmlDocument.DocumentElement.NamespaceURI)
                {
                    case SAML.NamespaceURIs.Assertion:
                        VerifyAssertion(xmlDocument.DocumentElement);
                        break;

                    case SAML.NamespaceURIs.Protocol:
                        VerifyMessage(xmlDocument.DocumentElement);
                        break;

                    case SAML.NamespaceURIs.Metadata:
                        VerifyMetadata(xmlDocument.DocumentElement);
                        break;

                    default:
                        throw new ArgumentException("Unexpected namespace URI " + xmlDocument.DocumentElement.NamespaceURI);
                }
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
