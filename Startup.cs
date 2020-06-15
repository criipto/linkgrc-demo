using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;

[assembly: OwinStartup(typeof(LinkGRC.Startup))]

namespace LinkGRC
{
    public class Startup
    {
        private string authority = System.Configuration.ConfigurationManager.AppSettings["oidc:authority"];
        private string clientId = System.Configuration.ConfigurationManager.AppSettings["oidc:client-id"];
        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(
                new CookieAuthenticationOptions
                {
                    // TODO: Triage all the available options here - there are quite a few.
                }
            );

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Passive,
                    Authority = authority,
                    ClientId = clientId,
                    ResponseType = OpenIdConnectResponseType.IdToken,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = notification =>
                        {
                            var pm = notification.ProtocolMessage;
                            pm.RedirectUri = notification.Request.Uri.AbsoluteUri;
                            return Task.CompletedTask;
                        },
                        AuthenticationFailed = notififaction =>
                        {
                            return Task.CompletedTask;
                        },
                        AuthorizationCodeReceived = notififaction =>
                        {
                            return Task.CompletedTask;
                        },
                        MessageReceived = notififaction =>
                        {
                            return Task.CompletedTask;
                        },
                        SecurityTokenReceived = notififaction =>
                        {
                            return Task.CompletedTask;
                        },
                        SecurityTokenValidated = notififaction =>
                        {
                            // The ClaimsPrincipal default behavior is to pull the Name from
                            // the System.Security.Claims.ClaimTypes.Name claim-type.
                            // Check for a fallback to the OIDC-default claim type ("name") in that case
                            var identity = notififaction.AuthenticationTicket.Identity;
                            if (string.IsNullOrWhiteSpace(identity.Name))
                            {
                                var nameClaim = notififaction.AuthenticationTicket.Identity.FindFirst("name");
                                if (nameClaim != null)
                                {
                                    notififaction.AuthenticationTicket.Identity.AddClaim(
                                        new Claim(ClaimTypes.Name, nameClaim.Value)
                                    );
                                }
                            }
                            return Task.CompletedTask;
                        },
                        TokenResponseReceived = notififaction =>
                        {
                            return Task.CompletedTask;
                        }
                    }
                }
            );
        }
    }
}
