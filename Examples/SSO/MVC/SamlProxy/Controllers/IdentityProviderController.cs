using ComponentSpace.SAML2;
using System;
using System.Web.Configuration;
using System.Web.Mvc;

namespace SamlProxy.Controllers
{
    [RoutePrefix("saml/idp")]
    [Route("{action}")]
    public class IdentityProviderController : Controller
    {
        public ActionResult SingleSignOnService()
        {
            // Receive an authn request from a service provider (SP-initiated SSO).
            string partnerName;

            SAMLIdentityProvider.ReceiveSSO(Request, out partnerName);

            // Determine the identity provider name.
            partnerName = GetIdentityProviderName();

            // Initiate SSO to the identity provider.
            SAMLServiceProvider.InitiateSSO(Response, null, partnerName);

            return new EmptyResult();
        }

        public ActionResult SingleLogoutService()
        {
            // Receive a single logout request or response from a service provider.
            // If a request is received then initiate SLO to the identity provider.
            // If a response is received then complete the SP-initiated SLO.
            bool isRequest;
            bool hasCompleted;
            string logoutReason;
            string partnerName;
            string relayState;

            SAMLIdentityProvider.ReceiveSLO(
                Request,
                Response,
                out isRequest,
                out hasCompleted,
                out logoutReason,
                out partnerName,
                out relayState);

            if (isRequest)
            {
                // Determine the identity provider name.
                partnerName = GetIdentityProviderName();

                // Initiate SLO to the identity provider.
                SAMLServiceProvider.InitiateSLO(Response, null, null, partnerName);
            }
            else
            {
                if (hasCompleted)
                {
                    // SP-initiated SLO has completed.
                    SAMLServiceProvider.SendSLO(Response, null);
                }
            }

            return new EmptyResult();
        }

        private string GetIdentityProviderName()
        {
            // In this example, the identity provider name is retrieved from a query string parameter or the configuration.
            var name = Request.QueryString["idp"];

            if (string.IsNullOrEmpty(name))
            {
                name = WebConfigurationManager.AppSettings["PartnerIdentityProviderName"];
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("An identity provider name is required.");
            }

            return name;
        }
    }
}