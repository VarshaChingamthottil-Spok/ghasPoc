using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;

using ComponentSpace.SAML2;

namespace ExampleIdentityProvider.SAML
{
    public partial class SSOService : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            try
            {
                // Either an authn request has been received or login has just completed in response to a previous authn request.
                // The IsSSOCompletionPending is true if an authn request was previously received, login has just completed
                // and control is being returned to this page. Otherwise, receive an an authn request.
                if (!(SAMLIdentityProvider.IsSSOCompletionPending() && User.Identity.IsAuthenticated))
                {
                    string partnerSP = null;

                    // Receive the authn request from the service provider (SP-initiated SSO).
                    SAMLIdentityProvider.ReceiveSSO(Request, out partnerSP);

                    // If the user isn't logged in at the identity provider, force the user to login.
                    if (!User.Identity.IsAuthenticated)
                    {
                        FormsAuthentication.RedirectToLoginPage();
                        return;
                    }
                }

                // The user is logged in at the identity provider.
                // Respond to the authn request by sending a SAML response containing a SAML assertion to the SP.
                // Use the configured or logged in user name as the user name to send to the service provider (SP).
                // Include some user attributes.
                string userName = WebConfigurationManager.AppSettings[AppSettings.SubjectName];

                if (string.IsNullOrEmpty(userName))
                {
                    userName = User.Identity.Name;
                }

                IDictionary<string, string> attributes = new Dictionary<string, string>();

                foreach (string key in WebConfigurationManager.AppSettings.Keys)
                {
                    if (key.StartsWith(AppSettings.Attribute))
                    {
                        attributes[key.Substring(AppSettings.Attribute.Length + 1)] = WebConfigurationManager.AppSettings[key];
                    }
                }

                SAMLIdentityProvider.SendSSO(Response, userName, attributes);
            }

            catch (Exception exception)
            {
                // In production application, we recommend logging the exception and redirecting the user to a generic error page.
                throw exception;
            }
        }
    }
}
