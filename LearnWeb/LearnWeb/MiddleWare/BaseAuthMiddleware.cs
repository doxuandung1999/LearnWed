using Jose;
using LearnWeb.BL;
using LearnWeb.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LearnWeb.MiddleWare
{
    public class BaseAuthMiddleware
    {
        private readonly RequestDelegate _next;
        //private ITest _iTest;
        public BaseAuthMiddleware(RequestDelegate next)
        {
            _next = next;

        }

        public string Decode(string token, string key, bool verify = true)
        {
            // tasck token lấy thông tin
            string[] parts = token.Split('.');
            string header = parts[0];
            string payload = parts[1];
            byte[] crypto = Base64Url.Decode(parts[2]);

            // lấy header trong token
            string headerJson = Encoding.UTF8.GetString(Base64Url.Decode(header));
            JObject headerData = JObject.Parse(headerJson);

            // lấy nội dung lưu trong token
            string payloadJson = Encoding.UTF8.GetString(Base64Url.Decode(payload));
            JObject payloadData = JObject.Parse(payloadJson);

            if (verify)
            {
                // giải mã key truyền vào để verify với thông tin các key trong token
                var keyBytes = Convert.FromBase64String(key); // your key here

                AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
                RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;

                // lấy các thông tin cần để check trong key
                RSAParameters rsaParameters = new RSAParameters();
                rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);

                // đang tạo 1 key mã hóa với các thông tin đã lấy từ key bằng 
                //cách kết hợp các thông số như header , payload từ token => mục đích sinh ra 1 đoạn mã hóa y như token

                // tạo hàm băm
                SHA256 sha256 = SHA256.Create();
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

                RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");
                // verify 
                if (!rsaDeformatter.VerifySignature(hash, Base64Url.Decode(parts[2])))
                    throw new ApplicationException(string.Format("Invalid signature"));
            }

            return payloadData.ToString();
        }

        public async Task Invoke(HttpContext httpContext)
        {
            string token = string.Empty;
            string key = string.Empty;
            if (httpContext.Request.Headers.ContainsKey("Authentication") && httpContext.Request.Headers.ContainsKey("key"))
            {
                token = httpContext.Request.Headers["Authentication"];
                key = httpContext.Request.Headers["key"];


                string user = Decode(token, key);
                User userobj = JsonConvert.DeserializeObject<User>(user);

                var claims = new List<Claim>
            {
                new Claim("User", userobj.user, "hihi"),
                new Claim("Pass", userobj.pass , "hihi")
            };

                var appIdentity = new ClaimsIdentity(claims , "hihi");

                var claimUser = new ClaimsPrincipal(new[] { appIdentity });

                httpContext.User = claimUser;
            }
            await _next(httpContext);
        }

        //public static class BasicAuthMiddlewareExtensions
        //{
        //    public static IApplicationBuilder UseBaseAuthMiddleware(this IApplicationBuilder builder)
        //    {
        //        return builder.UseMiddleware<BaseAuthMiddleware>();
        //    }
        //}
    }
}
