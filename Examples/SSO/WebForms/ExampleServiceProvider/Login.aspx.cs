using System;
using System.Configuration;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient;
using System.Web;
using System.Web.Configuration;

using ComponentSpace.SAML2;

namespace ExampleServiceProvider
{
    public static class AppSettings
    {
        public const string PartnerIdP = "PartnerIdP";
    }

    public partial class Login : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            if(Session["Validuser"] != null)
                errorMessageLabel.Text = "Invalid credentials. Please register user in the application";
        }

        protected void ssoLinkButton_Click(object sender, EventArgs e)
        {
            // Remember the return URL.
            string returnUrl = Request.QueryString["ReturnUrl"];

            // To login at the service provider, initiate single sign-on to the identity provider (SP-initiated SSO).
            string partnerIdP = WebConfigurationManager.AppSettings[AppSettings.PartnerIdP];

            SAMLServiceProvider.InitiateSSO(Response, returnUrl, partnerIdP);
        }
    }
}
