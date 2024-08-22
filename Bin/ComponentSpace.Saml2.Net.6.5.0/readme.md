# SAML for ASP.NET

ComponentSpace.Saml2.Net enables SAML v2.0 identity provider (IdP) and service provider (SP) single sign-on (SSO) in ASP.NET applications.

Supports:

* Acting as the SAML service provider (SP)
* Acting as the SAML identity provider (IdP)
* Service provider initiated SSO
* Identity provider initiated SSO
* Setting and retrieving SAML attributes
* Logout
* SAML metadata creation and consumption
* ASP.NET Identity integration

Profiles:

* Web browser single sign-on (identity provider and service provider initiated)
* Single logout
* Artifact resolution
* Identity provider discovery
* Authentication, attribute and assertion query
* Name identifier management and mapping

## Licensing

ComponentSpace.Saml2.Net is a fully functional evaluation version of a commercial product. The trial period is 30 days.

A product license is available for purchase.

## Examples

Example ASP.NET projects are available that demonstrate the simple to use SAML API and accompanying SAML configuration.

### Initiating SSO from the SP

```
// SP-initiated SSO.
SAMLServiceProvider.InitiateSSO(Response, returnUrl, partnerIdP);
```

### Initiating SSO from the IdP

```
// IdP-initiated SSO.
SAMLIdentityProvider.InitiateSSO(Response, userName, attributes, targetUrl, partnerSP); 
```

### Receiving the SAML Response

```
// SP or IdP-initiated SSO.
SAMLServiceProvider.ReceiveSSO(
  Request, 
  out isInResponseTo, 
  out partnerIdP, 
  out authnContext, 
  out userName, 
  out attributes, 
  out targetUrl);
```

## Links

* [SAML for ASP.NET](https://www.componentspace.com/saml-for-asp-net)
