using ComponentSpace.SAML2;
using ComponentSpace.SAML2.Assertions;
using System;
using System.Web.Configuration;
using System.Web.Mvc;

namespace SamlProxy.Controllers
{
    [RoutePrefix("saml/sp")]
    [Route("{action}")]
    public class ServiceProviderController : Controller
    {
        public ActionResult AssertionConsumerService()
        {
            // Receive a SAML response from an identity provider either as part of IdP-initiated or SP-initiated SSO.
            bool isInResponseTo;
            string partnerName;
            string authnContext;
            string userName;
            SAMLAttribute[] attributes;
            string relayState;

            SAMLServiceProvider.ReceiveSSO(
                Request,
                out isInResponseTo,
                out partnerName,
                out authnContext,
                out userName,
                out attributes,
                out relayState);

            if (isInResponseTo)
            {
                // Complete SP-initiated SSO to the service provider.
                SAMLIdentityProvider.SendSSO(Response, userName, attributes, authnContext, null);
            }
            else
            {
                // Determine the service provider name.
                partnerName = GetServiceProviderName();

                // Initiate SSO to the service provider.
                SAMLIdentityProvider.InitiateSSO(Response, userName, attributes, authnContext, relayState, partnerName, null);
            }

            return new EmptyResult();
        }

        public ActionResult SingleLogoutService()
        {
            // Receive a single logout request or response from an identity provider.
            // If a request is received then initiate SLO to the identity provider.
            // If a response is received then complete the SP-initiated SLO.
            bool isRequest;
            string logoutReason;
            string partnerName;
            string relayState;

            SAMLServiceProvider.ReceiveSLO(
                Request,
                out isRequest,
                out logoutReason,
                out partnerName,
                out relayState);

            if (isRequest)
            {
                // Request logout at the service provider(s).
                SAMLIdentityProvider.InitiateSLO(Response, logoutReason, relayState);
            }
            else
            {
                // Respond to the SP-initiated SLO request indicating successful logout.
                SAMLIdentityProvider.SendSLO(Response, null);
            }

            return new EmptyResult();
        }

        private string GetServiceProviderName()
        {
            // In this example, the service provider name is retrieved from a query string parameter or the configuration.
            var name = Request.QueryString["sp"];

            if (string.IsNullOrEmpty(name))
            {
                name = WebConfigurationManager.AppSettings["PartnerServiceProviderName"];
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("A service provider name is required.");
            }

            return name;
        }
    }
}