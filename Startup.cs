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
using Microsoft.Owin.Security.Jwt;
using System.Net.Http;
using Microsoft.IdentityModel.Protocols;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Threading;
using System.Collections.Generic;

[assembly: OwinStartup(typeof(LinkGRC.Startup))]

namespace LinkGRC
{
    public class Startup
    {
        private HttpClient sharedClient = new HttpClient();
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
                    ResponseType = OpenIdConnectResponseType.IdTokenToken,
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
                        SecurityTokenValidated = context =>
                        {
                            SetupWithDefaults(context.AuthenticationTicket.Identity);
                            return Task.CompletedTask;
                        }
                    }
                }
            );

            string discoveryEndpoint = string.Format("{0}/.well-known/openid-configuration", authority);
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryEndpoint, new OpenIdConnectConfigurationRetriever(), sharedClient);
            app.UseJwtBearerAuthentication(
                new JwtBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active,
                    AllowedAudiences = new [] { clientId },
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidAudience = clientId,
                        ValidIssuers = new[] { authority, $"{authority}/" },
                        IssuerSigningKeyResolver = (rawToken, secToken, kid, validationParameters) =>
                        {
                            var task = configManager.GetConfigurationAsync();
                            task.ConfigureAwait(false);
                            task.Wait();
                            var discoveryDocument = task.Result;
                            return discoveryDocument.SigningKeys;
                        },
                    },
                    Provider = new OAuthBearerAuthenticationProvider
                    {
                        OnValidateIdentity = context =>
                        {
                            if (context.IsValidated)
                            {
                                SetupWithDefaults(context.Ticket.Identity);
                            }
                            return Task.CompletedTask;
                        }
                    }
                }
            );

        }
        private static void SetupWithDefaults(ClaimsIdentity identity)
        {
            if (identity is null)
            {
                throw new System.ArgumentNullException(nameof(identity));
            }

            // The ClaimsPrincipal default behavior is to pull the Name from
            // the System.Security.Claims.ClaimTypes.Name claim-type.
            // Check for a fallback to the OIDC-default claim type ("name") in that case

            if (string.IsNullOrWhiteSpace(identity.Name))
            {
                var nameClaim = identity.FindFirst("name");
                if (nameClaim != null)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Name, nameClaim.Value));
                }
            }

        }

    }
}
