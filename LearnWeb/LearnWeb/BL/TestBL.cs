using Jose;
using LearnWeb.Attributes;
using Nancy.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LearnWeb.BL
{
    public class TestBL : ITest
    {
        public string Get()
        {
            string a = "hi";
            return a;
        }

        public string GenToken(string userName, string pass)
        {

            string json = @"{
    ""p"": ""8aIEFY5NnYRJha-IhIKu6La56WclMUIYOETRkhCv9Ffui0KrkQi0e4kRQ9hyX1_OFg2Aqf2rJ9zQzWLAgin5lgG4XQvin7yvu5ZCePl6cSFitj6VTiejevEUZBTZhFpjp7E8Xn4vSBBASv9uEhusIM0zZDMloPMP3QjTEIAy_1U"",
    ""kty"": ""RSA"",
    ""q"": ""teNpeq6S0MtxdwhaezMv8zD4la_LH_Vg07JUKdYStXaVZ13M8Ryq9jQu_emWa3os_fxCM-ukVHDqni92cvVsTLZgDyw0xmo1_K8ujwGKQa8VLqj5vPo9zkpfC2KHhaj7AkFugsBVEXC-6J1Cmcdju2DrXxhUt_VEjxRU3RYoJPM"",
    ""d"": ""eodrpuaEDSIc_1NQLrMZx-PPXeV32niDrSnpmUZ7-by_J8FNegiogYrMHunood4DEPZCd-guaX0CC2kMAjWBXF5xYmCRBov6vGaGqqPbSYgR3b-eWwW7bvtoCd7Jkm7Ht_6h8xXQ8LI59M5thCkbNmwv1tuGtUeSiZQJox21lWOHV2quq1YtHe_7KP8ugK35yEHhFYYIW-GbKvseglA4QCzZjHBib0rMdlq8gP_DXImK1dwwB4x_qEgWwsiAGaTMVAdHG4M5bOYeNlWjL_4Xq7nh2HcrKKfrCWIAKjO9AUtZKA_pzdKygKesliD1vGjF3jJiRdqKdjk0yoPwd9U38Q"",
    ""e"": ""AQAB"",
    ""use"": ""sig"",
    ""kid"": ""1xKtlO6PtDljgl_jwjBxfJyHGnoQcc8bNQHZVdXk3GM"",
    ""qi"": ""mu0_0YMqXyTY3KopsWsN3H9TKDfi3McullS9RWO1AIXi7I4eOnWlhjS1ypnGOptw79_lESd7sz4fxt7iCdIAl0g16Nl8KdM2jKazsp3CDckXpK9XM9gPx9EAo8uTl1__LhJtc10QR37pGMgc-JT2ZvYMRQa8lc-I4fNiN8YOj5E"",
    ""dp"": ""FxZ5-W1NcT2QoNty2eZ6u_WpsemPHjPIiKfatnAtv9UfD-Ng7Uy9oggoxCjMVNycnnLP1m5MilSJBvbmmglUtcaYTRuznbuztuLWmySLVH_yJKO6NGuJLVgXsLBlUEYqu30t3YGFFwemfQQHCmfmfIPe4zYX5FcVLvOG5064kLk"",
    ""alg"": ""RS256"",
    ""dq"": ""WayoGWMuYSCcbVpB-dGvx0-Sj4IfPD9nIJggJIw1px-y40Z8vzcqFr59mJPspEqVGhefsCdyWmtdUOYHmP_lCCE2VOSvlE9TFKRt6PWSa3XdlKackg4yIJ3MJDnMpRo9vsvxpycaCcIzbU3zQwvp4L0U7kp5okSbK4uTl3jQC_8"",
    ""n"": ""q64zHBxjixV_yJHjkplnRbmy-DjG3wVdTdj1eeirYDBMvGjOYIOLR_1cMBCt-n9gLdmkJqIEaNcMKeAZdPgPxdo5Hz2GjrNqhSKeLgKM0fetdAyh7nFUPD3oGbIEDonebp0iFcghZlqVdG_4khpghX9I0fewfadP_ZWCtF5ngLrCbqjvtgudyTT9OijxU4gzNrHK0s3vNuR6n9Hca2wJqkoSy0JffQa2bu0aVsudoliOSyYVQ98pZqfENS2uD3RHoE6aGWOUQhtzOYrI-5sCtcSaZ_8nJ163rRQlVBZ614KUuxlnR5VOoXblDLvFK1qR3EP192HfiihIGWT7D5hRrw""
}";

            var js = new JavaScriptSerializer();
            var jwk = js.Deserialize<IDictionary<string, string>>(json);


            // tạo key
            byte[] p = Base64Url.Decode(jwk["p"]);
            byte[] q = Base64Url.Decode(jwk["q"]);
            byte[] d = Base64Url.Decode(jwk["d"]);
            byte[] e = Base64Url.Decode(jwk["e"]);
            byte[] qi = Base64Url.Decode(jwk["qi"]);
            byte[] dq = Base64Url.Decode(jwk["dq"]);
            byte[] dp = Base64Url.Decode(jwk["dp"]);
            byte[] n = Base64Url.Decode(jwk["n"]);
            RSA key = RSA.Create();
            RSAParameters keyParams = new RSAParameters();
            keyParams.P = p;
            keyParams.Q = q;
            keyParams.D = d;
            keyParams.Exponent = e;
            keyParams.InverseQ = qi;
            keyParams.DP = dp;
            keyParams.DQ = dq;
            keyParams.Modulus = n;

            key.ImportParameters(keyParams);

            //var payload = new Dictionary<string, object>();
            var payload = new
            {
                user = userName,
                pass = pass
            };


            string tokenSigned = JWT.Encode(payload, key, JwsAlgorithm.RS256);


            return tokenSigned;
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


    }
}
