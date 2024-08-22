using System;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml;

using ComponentSpace.SAML2.Assertions;
using ComponentSpace.SAML2.Utility;

namespace DecryptAssertion
{
    /// <summary>
    /// Decrypts SAML v2.0 assertions.
    /// 
    /// Usage: DecryptAssertion -c <certificateFileName> -p <password> <filename>
    /// 
    /// where the file contains a SAML assertion.
    /// 
    /// The decrypted SAML assertion is written to standard output.
    /// </summary>
    static class Program
    {
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
                throw new ArgumentException("Missing SAML assertion file.");
            }
        }

        private static void ShowUsage()
        {
            Console.Error.WriteLine("Usage: DecryptAssertion -c <certificateFileName> -p <password> <filename>");
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

        private static XmlElement DecryptAssertion(XmlElement xmlElement)
        {
            Console.Error.WriteLine("Decrypting SAML assertion");

            EncryptedAssertion encryptedAssertion = new EncryptedAssertion(xmlElement);

            return encryptedAssertion.DecryptToXml(CertificateHelper.GetPrivateKey(x509Certificate));
        }

        static void Main(string[] args)
        {
            try
            {
                ParseArguments(args);
                LoadKeyAndCertificate();

                XmlDocument xmlDocument = LoadXmlDocument();

                Console.WriteLine(DecryptAssertion(xmlDocument.DocumentElement).OuterXml);
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
