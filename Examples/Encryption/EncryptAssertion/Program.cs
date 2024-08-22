using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.IO;
using System.Xml;

using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Assertions;

namespace EncryptAssertion
{
    /// <summary>
    /// Encrypts SAML v2.0 assertions.
    /// 
    /// Usage: EncryptAssertion [-k <keyAlgorithm>] [-d <dataAlgorithm>] -c <certificateFileName> <filename>
    /// 
    /// where the file contains a SAML assertion,
    /// the key encryption method defaults to http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
    /// and the data encryption method defaults to http://www.w3.org/2001/04/xmlenc#aes256-cbc.
    /// 
    /// The encrypted SAML assertion is written to standard output.
    /// </summary>
    static class Program
    {
        private static string keyEncryptionMethod = SAMLIdentifiers.KeyEncryptionMethods.RSA_OAEP_MGF1P;
        private static string dataEncryptionMethod = SAMLIdentifiers.DataEncryptionMethods.AES_256;
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
                        case "k":
                            if (++i < args.Length)
                            {
                                keyEncryptionMethod = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing key encryption method.");
                            }
                            break;

                        case "d":
                            if (++i < args.Length)
                            {
                                dataEncryptionMethod = args[i];
                            }
                            else
                            {
                                throw new ArgumentException("Missing data encryption method.");
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

            if (string.IsNullOrEmpty(fileName))
            {
                throw new ArgumentException("Missing SAML assertion file.");
            }
        }

        private static void ShowUsage()
        {
            Console.Error.WriteLine("EncryptAssertion [-k <keyAlgorithm>] [-d <dataAlgorithm>] -c <certificateFileName> <filename>");
        }

        private static void LoadCertificate()
        {
            Console.Error.WriteLine("Loading certificate " + certificateFileName);

            if (!File.Exists(certificateFileName))
            {
                throw new ArgumentException("The certificate file " + certificateFileName + " doesn't exist.");
            }

            x509Certificate = new X509Certificate2(certificateFileName);
        }

        private static XmlDocument LoadXmlDocument()
        {
            Console.Error.WriteLine("Loading " + fileName);

            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(fileName);

            return xmlDocument;
        }

        private static XmlElement EncryptAssertion(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Encrypting SAML assertion");

            return new EncryptedAssertion(xmlElement, x509Certificate, new EncryptionMethod(keyEncryptionMethod), new EncryptionMethod(dataEncryptionMethod)).ToXml();
        }

        static void Main(string[] args)
        {
            try
            {
                ParseArguments(args);
                LoadCertificate();

                XmlDocument xmlDocument = LoadXmlDocument();

                Console.WriteLine(EncryptAssertion(xmlDocument.DocumentElement).OuterXml);
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
