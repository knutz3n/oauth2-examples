using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography.X509Certificates;

namespace ClientAssertionSample
{

    class FrameworkClientAssertionSampleProgram
    {
        static void Main(string[] args)
        {
            var program = new FrameworkClientAssertionSampleProgram();

            // The X509Certificate2 instance, should typically be fetched from the current user's X509Store.
            // See https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=netframework-4.8
            X509Certificate2 certificate = new X509Certificate2("certificate.pfx", "<password>");
            RSA privateKey = certificate.GetRSAPrivateKey();

            string issuer = "https://localhost/auth/realms/example";
            string clientId = "example-client-id";

            string clientAssertion = program.GetSignedClientAssertion(privateKey, issuer, clientId);
            Console.WriteLine("Using client assertion: " + clientAssertion);

            string tokenResponse = program.FetchToken(issuer + "/protocol/openid-connect/token", clientAssertion);

            // TODO: parse token response as JSON and extract the access token
            Console.WriteLine(tokenResponse);
        }

        private string FetchToken(string tokenEndpoint, string clientAssertion)
        {
            var dict = new Dictionary<string, string>();
            dict.Add("grant_type", "client_credentials");
            dict.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            dict.Add("client_assertion", clientAssertion);

            var client = new HttpClient();
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) {
                Content = new FormUrlEncodedContent(dict)
            };
            using (var tokenResponseContent = client.SendAsync(tokenRequest).Result.Content) {
                return tokenResponseContent.ReadAsStringAsync().Result;
            }
        }

        private IDictionary<string, object> GetClaims(string assertionAudience, string clientId)
        {
            const uint JwtLifetimeInSeconds = 60 * 5; // Five minutes
            DateTimeOffset issuedAt = DateTimeOffset.UtcNow;
            DateTimeOffset validFrom = issuedAt.AddSeconds(-JwtLifetimeInSeconds);
            DateTimeOffset validUntil = issuedAt.AddSeconds(JwtLifetimeInSeconds);

            return new Dictionary<string, object>()
            {
                { "aud", assertionAudience },
                { "iat", issuedAt.ToUnixTimeSeconds() },
                { "nbf", validFrom.ToUnixTimeSeconds() },
                { "exp", validUntil.ToUnixTimeSeconds() },
                { "iss", clientId },
                { "jti", Guid.NewGuid().ToString() },
                { "sub", clientId }
            };
        }

        private string GetSignedClientAssertion(RSA rsa, string tenantId, string clientId)
        {
            var header = new Dictionary<string, string>()
            {
                { "alg", "RS256"},
                { "typ", "JWT" }
            };

            var claims = GetClaims(tenantId, clientId);

            var headerBytes = JsonSerializer.SerializeToUtf8Bytes(header);
            var claimsBytes = JsonSerializer.SerializeToUtf8Bytes(claims);
            string token = Base64UrlEncode(headerBytes) + "." + Base64UrlEncode(claimsBytes);

            string signature = Base64UrlEncode(
                    rsa.SignData(Encoding.UTF8.GetBytes(token),
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1)
                    );
            return string.Concat(token, ".", signature);
        }

        private string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
              .Split('=')[0]
              .Replace('+', '-')
              .Replace('/', '_');
        }

    }
}
