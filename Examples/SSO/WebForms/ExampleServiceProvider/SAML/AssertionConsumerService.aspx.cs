using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using ComponentSpace.SAML2;

namespace ExampleServiceProvider.SAML
{
    public partial class AssertionConsumerService : System.Web.UI.Page
    {
        public const string AttributesSessionKey = "saml-attributes";

        protected void Page_Load(object sender, EventArgs e)
        {
            try
            {
                bool isInResponseTo = false;
                string partnerIdP = null;
                string authnContext = null;
                string userName = null;
                IDictionary<string, string> attributes = null;
                string targetUrl = null;

                // Receive and process the SAML assertion contained in the SAML response.
                // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
                SAMLServiceProvider.ReceiveSSO(Request, out isInResponseTo, out partnerIdP, out authnContext, out userName, out attributes, out targetUrl);

                string ProfileId = string.Empty;
                if (string.IsNullOrEmpty(userName))
                {
                    throw new ArgumentException("A SAML Name ID is expected to be returned by the identity provider.");
                }
                else
                {
                    string connectionString = ConfigurationManager.ConnectionStrings["DbSource"].ConnectionString;
                    string queryString = "select ProfileId from xkm where [name] = '" + userName + "'";

                    using (SqlConnection connection = new SqlConnection(
                       connectionString))
                    {
                        SqlCommand command = new SqlCommand(queryString, connection);
                        command.Connection.Open();
                        ProfileId = (string)command.ExecuteScalar();
                    }                   
                }

                // If a target URL is supplied, ensure it's local to avoid potential open redirection attacks.
                if (targetUrl != null && !IsLocalUrl(targetUrl))
                {
                    Session["Validuser"] = null;
                    targetUrl = null;
                }

                // If no target URL is provided, provide a default.
                if (targetUrl == null)
                {
                    Session["Validuser"] = null;
                    targetUrl = "~/";
                }
                if (String.IsNullOrEmpty(ProfileId) || Session["Validuser"] != null)
                {
                    Session["Validuser"] = "false";
                    // Logout locally.
                    FormsAuthentication.SignOut();

                    if (SAMLServiceProvider.CanSLO(WebConfigurationManager.AppSettings[AppSettings.PartnerIdP]))
                    {
                        // Request logout at the identity provider.
                        SAMLServiceProvider.InitiateSLO(Response, null, null, partnerIdP);
                    }
                    targetUrl = "https://mcdevenv.spokvdev.com:444/login.aspx";
                }

                // Login automatically using the asserted identity.
                // This example uses forms authentication. Your application can use any authentication method you choose.
                // There are no restrictions on the method of authentication.
                FormsAuthentication.SetAuthCookie(userName.ToString(), false);

                // Save the attributes.
                Session[AttributesSessionKey] = attributes;

                // Redirect to the target URL.
                Response.Redirect(targetUrl, false);
            }

            catch (Exception exception)
            {
                // In production application, we recommend logging the exception and redirecting the user to a generic error page.
                throw exception;
            }
        }

        private bool IsLocalUrl(string url)
        {
            Uri uri;

            if (Uri.TryCreate(url, UriKind.Relative, out uri))
            {
                return true;
            }

            if (Uri.TryCreate(url, UriKind.Absolute, out uri) && uri.Host.Equals(Request.Url.Host, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }
    }
}
