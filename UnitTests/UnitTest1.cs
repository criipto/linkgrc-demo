using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;

namespace UnitTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void ValidateSdcAccessToken()
        {
            // Arrange
            // Read your client-id from a config file/db somewhere
            var linkGRCClientId = "https://tac-test.sdc.dk";
            // Get this from OIDC discovery doc instead of hardcoding it
            var sdcIssuer = "https://idp-test.sdc.dk"; 
            // Sample token sent via mail by SDC. Real usage will pick it from either a query- or an form-post-param
            var id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IklkcFRva2VuU2lnbmluZ0tleS8xODFkMThkYzRjYjA0ZjRjOTg2NDFjOTY3MGJlN2FmZCIsIng1dCI6IllSU2V3WHRnc3J4QnphWl9HaDhoUkVGaGlDbyJ9.eyJpc3MiOiJodHRwczovL2lkcC10ZXN0LnNkYy5kayIsImF1ZCI6Imh0dHBzOi8vdGFjLXRlc3Quc2RjLmRrIiwic3ViIjoiRDczMDkzMiIsInN1YnQiOiJiYW5rZW1wIiwiaWF0IjoiMTYwMDA4Mjc5MiIsIm5iZiI6IjE2MDAwODI3OTIiLCJleHAiOiIxNjAwMTExNjAyIiwianRpIjoiN2RlMmU3ZjctNmRhNy00MzE1LTg3NzgtNDU5ZGUxMTMwNzJhIiwidHlwZSI6ImFjY2VzcyIsImFjciI6NCwiYW1yIjoiU2RjQWRMb2dvbiIsInNjcGUiOiJDUkJPIiwiY2xpZW50X2lkIjoiODc1OTQ2ZTMtODcyZi00MzBkLThhY2UtNjc5MjRhMjM3MTdlIiwidXJuOnNkYy5kazpvcmdpZCI6IjQ3MzAiLCJ1cm46c2RjLmRrOm9yZ2lkdCI6Imlkb3IiLCJ1cm46c2RjLmRrOmNudHkiOiJOTyIsInVybjpzZGMuZGs6Y2hubCI6ImludG4iLCJhY3QiOnsic3ViIjoiRDczMDkzMiJ9LCJ1cm46c2RjLmRrOnB3ZCI6Im12YUc2SlpTWll5c2ZMQVdBMGlnRWtaMERhRktHb1dZY1NaRTNweEs2YUFmUU1WQ3RSRjR0dGY2TU5JN044WWs1NVYzNUlSSUhDbVZXSmRTbVVidEYxS0lWQkZoMUZVRHQvY1Z4RDUya3ZQcjg3TnVsNE44WDE3UnZENG11VmltWkY2c2NZNFZqUWdMZGZENFR3MFNBbkZSa05oN0ErbGVJQ3R6QTlYMW1hdVczK1Y2WUUyR3VPd3N5d2QyUnVNMGdXeVdaMDNzSDE2RUJYYzhnK21WTU4xSW1YbkovVklrcDdNTXE3RXNvanBkTGVUV1hSakcrWS9Qa1JCUlpqSWJNU2I4YjZ3VHBKc2RRTU1hRk5iQkl6a3VaR255SUFLcG10M1BsKzlFWitXQm5jVkxkTjFYKytNSW5qWWpQOFpWL0pKcTVPODc2ZlJVenNsTGJVSGlUUT09In0.bmLG1oTA9N0OP2k2WGz7THt0CSqsQJdK3uJvzjAeYhbymbOd6pBwh71OwlGkNunx1wkpQspfYq-AVcnJy20AuFBwRAgS_rjpuvWyPbtRSj1VvtTUEo-yHjyIVGJ5_OorVgmVwhWXBnMnyFYrRDXJAGmrhBluvr0Mlt-wpfGfFlpnUNxZ33w3THyELR0WE5Raotzh4zEYXZyDW0wP0NhywUnr_OAWpPAaBYjONRIJf3w3NwfkX5Vunq0syZ3cDjGDVXGMyPn94az6Ab2VnlAidm5atkNG_Za2a4SQRFQ1ohSpfOBiNoxG16dMemAd2i4BzEYPvMNDvTbyJi6uaWYF4Q";
            // Json Web Key Set sent via mail by SDC, will be part of the OIDC Discovery Document
            var jwksJson = System.IO.File.ReadAllText("jwks.json");
            var jwks = JsonConvert.DeserializeObject<JsonWebKeySet>(jwksJson);
            var signingKeys = jwks.GetSigningKeys();
            var tokenHandler = new JwtSecurityTokenHandler
            {
                MapInboundClaims = false
            };
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKeys = signingKeys,
                ValidateAudience = true,
                ValidAudience = linkGRCClientId,
                ValidateIssuer = true,
                ValidIssuer = sdcIssuer,
                ClockSkew = TimeSpan.FromMinutes(5),
                ValidateLifetime = false // TODO: Set to true for non-unit-testing purposes
            };

            // Act
            SecurityToken validatedToken = null;
            ClaimsPrincipal claimsPrincipal =
                tokenHandler.ValidateToken(id_token, validationParameters, out validatedToken);

            // Assert
            Assert.IsNotNull(validatedToken);
            Assert.IsNotNull(claimsPrincipal);
            Assert.IsInstanceOfType(validatedToken, typeof(JwtSecurityToken));
            JwtSecurityToken jwt = (JwtSecurityToken)validatedToken;
            Assert.IsNotNull(jwt.Subject);
            // Pick out some claim values.
            // Paste the id_token value into jwt.io to see all available properties
            var orgId = claimsPrincipal.FindFirst("urn:sdc.dk:orgid");
            Assert.IsNotNull(orgId);
            Assert.AreEqual("4730", orgId.Value);
            var orgIdT = claimsPrincipal.FindFirst("urn:sdc.dk:orgidt");
            Assert.IsNotNull(orgIdT);
            Assert.AreEqual("idor", orgIdT.Value);
        }
    }
}
