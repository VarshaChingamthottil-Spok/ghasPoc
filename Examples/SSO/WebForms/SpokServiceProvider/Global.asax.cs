using System;
using System.Collections.Generic;

using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Configuration;
using ComponentSpace.SAML2.Configuration.Resolver;
using ComponentSpace.SAML2.Data;

namespace SpokServiceProvider
{
    public class Global : System.Web.HttpApplication
    {
        // SAML configuration may be specified using one of the following approaches:
        //
        // (1) using a saml.config file in the application's directory that's loaded automatically
        // (2) programmatically by calling the SAML configuration API
        // (3) programmatically by implementing the ISAMLConfigurationResolver interface
        //
        // The saml.config file is the simplest approach and requires no additional coding.
        //
        // If SAML configuration information is stored in a database, it must be set programmatically.
        //
        // If the SAML configuration changes infrequently, it may be set using the SAML configuration API, 
        // typically at application start-up.
        //
        // If the SAML configuration changes frequently, it's better to implement the ISAMLConfigurationResolver interface
        // for the on-demand retrieval of SAML configuration information.
        //
        // The following code demonstrates the two approaches to setting the configuration programmatically.



        // This class demonstrates loading configuration programmatically by implementing the ISAMLConfigurationResolver interface.
        // This interface supports the on-demand retrieval of SAML configuration information.
        // Alternatively, configuration may be loaded programmatically by calling the SAML configuration API.
        // Either of these approaches may be used if you wish to store configuration in a custom database, for example.
        // If not configured programmatically, configuration is loaded automatically from the saml.config file 
        // in the application's directory.
        public class SpokServiceProviderConfigurationResolver : AbstractSAMLConfigurationResolver
        {
            /// <summary>
            /// Gets the <c>LocalServiceProviderConfiguration</c>.
            /// </summary>
            /// <param name="configurationName">The configuration name or <c>null</c> if none.</param>
            /// <returns>The local service provider configuration.</returns>
            /// <exception cref="SAMLException">
            /// Thrown when the local service provider configuration cannot be found.
            /// </exception>
            public override LocalServiceProviderConfiguration GetLocalServiceProviderConfiguration(string configurationName)
            {
                return new LocalServiceProviderConfiguration()
                {
                    Name = "https://SpokServiceProvider",
                    AssertionConsumerServiceUrl = "~/SAML/AssertionConsumerService.aspx",
                    LocalCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\sp.pfx",
                            Password = "password"
                        }
                    }
                };
            }

            /// <summary>
            /// Gets the <c>PartnerIdentityProviderConfiguration</c> given the partner name.
            /// </summary>
            /// <param name="configurationName">The configuration name or <c>null</c> if none.</param>
            /// <param name="partnerName">The partner name.</param>
            /// <returns>The partner identity provider configuration.</returns>
            /// <exception cref="SAMLException">
            /// Thrown when the partner identity provider configuration cannot be found.
            /// </exception>
            public override PartnerIdentityProviderConfiguration GetPartnerIdentityProviderConfiguration(string configurationName, string partnerName)
            {
                return new PartnerIdentityProviderConfiguration()
                {
                    Name = "https://ExampleIdentityProvider",
                    SingleSignOnServiceUrl = "https://MCDEVENV:443/SAML/SSOService.aspx",
                    SingleLogoutServiceUrl = "https://MCDEVENV:443/SAML/SLOService.aspx",
                    PartnerCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\idp.cer",
                        }
                    }
                };
            }
        }

        // This method demonstrates loading configuration programmatically by calling the SAML configuration API.
        // Alternatively, configuration may be loaded programmatically by implementing the ISAMLConfigurationResolver interface.
        // Either of these approaches may be used if you wish to store configuration in a custom database, for example.
        // If not configured programmatically, configuration is loaded automatically from the saml.config file 
        // in the application's directory.
        private static void LoadSAMLConfigurationProgrammatically()
        {
            SAMLConfiguration samlConfiguration = new SAMLConfiguration()
            {
                LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
                {
                    Name = "https://SpokServiceProvider",
                    AssertionConsumerServiceUrl = "~/SAML/AssertionConsumerService.aspx",
                    LocalCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\sp.pfx",
                            Password = "password"
                        }
                    }
                }
            };

            samlConfiguration.AddPartnerIdentityProvider(
                new PartnerIdentityProviderConfiguration()
                {
                    Name = "https://ExampleIdentityProvider",
                    SingleSignOnServiceUrl = "https://MCDEVENV:443/SAML/SSOService.aspx",
                    SingleLogoutServiceUrl = "https://MCDEVENV:443/SAML/SLOService.aspx",
                    PartnerCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\idp.cer",
                        }
                    }
                });

            SAMLController.Configuration = samlConfiguration;
        }

        // This method demonstrates loading multi-tenanted configuration programmatically by calling the SAML configuration API.
        // Alternatively, configuration is loaded automatically from the multi-tenanted saml.config file in the application's directory.
        private static void LoadMultiTenantedSAMLConfigurationProgrammatically()
        {
            SAMLConfigurations samlConfigurations = new SAMLConfigurations();

            SAMLConfiguration samlConfiguration = new SAMLConfiguration()
            {
                Name = "tenant1",

                LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
                {
                    Name = "https://SpokServiceProvider",
                    AssertionConsumerServiceUrl = "~/SAML/AssertionConsumerService.aspx",
                    LocalCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\sp.pfx",
                            Password = "password"
                        }
                    }
                }
            };

            samlConfiguration.AddPartnerIdentityProvider(
                new PartnerIdentityProviderConfiguration()
                {
                    Name = "https://ExampleIdentityProvider",
                    SingleSignOnServiceUrl = "https://MCDEVENV:443/SAML/SSOService.aspx",
                    SingleLogoutServiceUrl = "https://MCDEVENV:443/SAML/SLOService.aspx",
                    PartnerCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\idp.cer",
                        }
                    }
                });

            samlConfigurations.AddConfiguration(samlConfiguration);

            samlConfiguration = new SAMLConfiguration()
            {
                Name = "tenant2",

                LocalServiceProviderConfiguration = new LocalServiceProviderConfiguration()
                {
                    Name = "https://SpokServiceProvider2",
                    AssertionConsumerServiceUrl = "~/SAML/AssertionConsumerService.aspx",
                    LocalCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\sp2.pfx",
                            Password = "password"
                        }
                    }
                }
            };

            samlConfiguration.AddPartnerIdentityProvider(
                new PartnerIdentityProviderConfiguration()
                {
                    Name = "https://ExampleIdentityProvider2",
                    SingleSignOnServiceUrl = "https://MCDEVENV:443/SAML/SSOService.aspx",
                    SingleLogoutServiceUrl = "https://MCDEVENV:443/SAML/SLOService.aspx",
                    PartnerCertificates = new List<CertificateConfiguration>()
                    {
                        new CertificateConfiguration()
                        {
                            FileName = @"certificates\idp2.cer",
                        }
                    }
                });

            samlConfigurations.AddConfiguration(samlConfiguration);

            SAMLController.Configurations = samlConfigurations;
        }

        // This method demonstrates using a database to store SAML identifiers and session data in a database.
        // This may be required in a web farm deployment when ASP.NET sessions are not stored in a database.
        private static void ConfigureSAMLDatabase()
        {
            SAMLController.SSOSessionStore = new DatabaseSSOSessionStore();
            SAMLController.IDCache = new DatabaseIDCache();
        }

        protected void Application_Start(object sender, EventArgs e)
        {
            //SAMLController.ConfigurationResolver = new SpokServiceProviderConfigurationResolver();
            //LoadSAMLConfigurationProgrammatically();
            //LoadMultiTenantedSAMLConfigurationProgrammatically();
            //ConfigureSAMLDatabase();
        }

        protected void Application_End(object sender, EventArgs e)
        {
        }
    }
}