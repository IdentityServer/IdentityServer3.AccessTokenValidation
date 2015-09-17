using IdentityModel;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace AccessTokenValidation.Tests.Util
{
    static class TokenFactory
    {
        public const string DefaultIssuer = "https://issuer";
        public const string DefaultAudience = "https://issuer/resources";
        public const string DefaultPublicKey = "MIIDBTCCAfGgAwIBAgIQNQb+T2ncIrNA6cKvUA1GWTAJBgUrDgMCHQUAMBIxEDAOBgNVBAMTB0RldlJvb3QwHhcNMTAwMTIwMjIwMDAwWhcNMjAwMTIwMjIwMDAwWjAVMRMwEQYDVQQDEwppZHNydjN0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnTksBdxOiOlsmRNd+mMS2M3o1IDpK4uAr0T4/YqO3zYHAGAWTwsq4ms+NWynqY5HaB4EThNxuq2GWC5JKpO1YirOrwS97B5x9LJyHXPsdJcSikEI9BxOkl6WLQ0UzPxHdYTLpR4/O+0ILAlXw8NU4+jB4AP8Sn9YGYJ5w0fLw5YmWioXeWvocz1wHrZdJPxS8XnqHXwMUozVzQj+x6daOv5FmrHU1r9/bbp0a1GLv4BbTtSh4kMyz1hXylho0EvPg5p9YIKStbNAW9eNWvv5R8HN7PPei21AsUqxekK0oW9jnEdHewckToX7x5zULWKwwZIksll0XnVczVgy7fCFwIDAQABo1wwWjATBgNVHSUEDDAKBggrBgEFBQcDATBDBgNVHQEEPDA6gBDSFgDaV+Q2d2191r6A38tBoRQwEjEQMA4GA1UEAxMHRGV2Um9vdIIQLFk7exPNg41NRNaeNu0I9jAJBgUrDgMCHQUAA4IBAQBUnMSZxY5xosMEW6Mz4WEAjNoNv2QvqNmk23RMZGMgr516ROeWS5D3RlTNyU8FkstNCC4maDM3E0Bi4bbzW3AwrpbluqtcyMN3Pivqdxx+zKWKiORJqqLIvN8CT1fVPxxXb/e9GOdaR8eXSmB0PgNUhM4IjgNkwBbvWC9F/lzvwjlQgciR7d4GfXPYsE1vf8tmdQaY8/PtdAkExmbrb9MihdggSoGXlELrPA91Yce+fiRcKY3rQlNWVd4DOoJ/cPXsXwry8pWjNCo5JD8Q+RQ5yZEy7YPoifwemLhTdsBz3hlZr28oCGJ3kbnpW0xGvQb3VHSTVVbeei0CfXoW6iz1";

        public const string Api1Scope = "api1";
        public const string Api2Scope = "api2";

        private static X509Certificate2 signingCert;

        public static X509Certificate2 DefaultSigningCertificate
        {
            get
            {
                if (signingCert == null)
                {
                    signingCert = Cert.Load();
                }

                return signingCert;
            }
        }

        public static JwtSecurityToken CreateToken(
            string issuer = null,
            string audience = null,
            IEnumerable<string> scope = null,
            int ttl = 360,
            List<Claim> additionalClaims = null,
            X509Certificate2 signingCertificate = null)
        {
            if (additionalClaims == null)
            {
                additionalClaims = new List<Claim>();
            }

            if (scope != null && scope.Any())
            {
                scope.ToList().ForEach(s => additionalClaims.Add(new Claim("scope", s)));
            }

            var credential = new X509SigningCredentials(signingCertificate ?? DefaultSigningCertificate);

            var token = new JwtSecurityToken(
                issuer ?? DefaultIssuer,
                audience ?? DefaultAudience,
                additionalClaims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddSeconds(ttl),
                credential);

            token.Header.Add(
                "kid", Base64Url.Encode(credential.Certificate.GetCertHash()));

            return token;
        }

        public static string CreateTokenString(JwtSecurityToken token)
        {
            JwtSecurityTokenHandler.OutboundClaimTypeMap = new Dictionary<string, string>();

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }
    }
}
