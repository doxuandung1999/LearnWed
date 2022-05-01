using LearnWeb.BL;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace LearnWeb.Attributes
{
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    {
    }
    public class CustomAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        //private readonly ICustomAuthenticationManager customAuthenticationManager;
        private readonly ITest itest;

        // muốn dùng hàm gì ở interfaxe gì, thì phải thêm hàm đấy vào CustomAuthenticationHandler 
        //để dùng trong hàm override HandleAuthenticateAsync
        public CustomAuthenticationHandler(
            IOptionsMonitor<BasicAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ITest itest)
             //ICustomAuthenticationManager customAuthenticationManager) 
            : base(options, logger, encoder, clock)
        {
            this.itest = itest;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authentication"))
                return AuthenticateResult.Fail("Unauthorized");

            string authorizationHeader = Request.Headers["Authentication"];
            string key = Request.Headers["key"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (!authorizationHeader.StartsWith("misa", StringComparison.OrdinalIgnoreCase))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            string token = authorizationHeader.Substring("misa".Length).Trim();
            if (string.IsNullOrEmpty(token))
            {
                return AuthenticateResult.Fail("Unauthorized");
            }

            try
            {
                return validateToken(token, key);
            }
            catch (Exception ex)
            {
                return AuthenticateResult.Fail(ex.Message);
            }
        }

        private AuthenticateResult validateToken(string token , string key)
        {
            var validatedToken = itest.Decode(token,key);
            if (validatedToken == null)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
            var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, validatedToken),
                };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new System.Security.Principal.GenericPrincipal(identity, null);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }


    }
}
