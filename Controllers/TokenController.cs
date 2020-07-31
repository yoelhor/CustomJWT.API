using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace CustomJWT.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly ILogger<TokenController> _logger;

        public TokenController(ILogger<TokenController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public string Get()
        {
            string issuer = "https://irisflower.b2clogin.com/84d5d499-6212-4bf7-8c02-3c8a6fe4306b/v2.0/";
            string aud = "63ba0d17-c4ba-47fd-89e9-31b3c2734339";
            string certThumbprint = "1ae88592bc50c52ed9602f8fc1cf581b234dce4b";

            // Sample: Load the certificate with a private key (must be pfx file)
            X509SigningCredentials signingCredentials;
            
            X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = certStore.Certificates.Find(
                                        X509FindType.FindByThumbprint,
                                        certThumbprint,
                                        false);
            // Get the first cert with the thumb-print
            if (certCollection.Count == 0)
            {
                throw new Exception("Certificate not found");
            }
            else
            {
                signingCredentials = new X509SigningCredentials(certCollection[0]);
            }


            // All parameters send to Azure AD B2C needs to be sent as claims
            IList<System.Security.Claims.Claim> claims = new List<System.Security.Claims.Claim>();
            claims.Add(new System.Security.Claims.Claim("name", "Alan Jackson", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("given_name", "Alan", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("family_name", "Jackson", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("acr", "b2c_1a_signup_signin", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("sub", "270a5abe-bfd5-4b54-972b-06a483c118cc", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("tid", "84d5d499-6212-4bf7-8c02-3c8a6fe4306b", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("ver", "1.0", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("nonce", "defaultNonce", System.Security.Claims.ClaimValueTypes.String, issuer));
            claims.Add(new System.Security.Claims.Claim("iat", DateTime.Now.Ticks.ToString(), System.Security.Claims.ClaimValueTypes.Integer64, issuer));
            claims.Add(new System.Security.Claims.Claim("auth_time", DateTime.Now.Ticks.ToString(), System.Security.Claims.ClaimValueTypes.Integer64, issuer));

            // Create the token
            JwtSecurityToken token = new JwtSecurityToken(
                    issuer,
                    aud,
                    claims,
                    DateTime.Now,
                    DateTime.Now.AddDays(7),
                    signingCredentials);

            // Get the representation of the signed token
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();

            return jwtHandler.WriteToken(token);
        }
    }
}
