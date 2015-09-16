using IdentityModel;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class DiscoveryEndpointHandler : WebRequestHandler
    {
        string _issuerName;
        X509Certificate2 _signingCertificate;

        public DiscoveryEndpointHandler()
            : this(TokenFactory.DefaultIssuer, TokenFactory.DefaultSigningCertificate)
        { }

        public DiscoveryEndpointHandler(string issuerName, X509Certificate2 signingCertificate)
        {
            _issuerName = issuerName;
            _signingCertificate = signingCertificate;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken cancellationToken)
        {
            if (request.RequestUri.AbsoluteUri.EndsWith("openid-configuration"))
            {
                var data = new Dictionary<object, object>
                {
                    { "issuer", _issuerName },
                    { "jwks_uri", "https://discodoc/jwks" }
                };

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ObjectContent<Dictionary<object, object>>(data, new JsonMediaTypeFormatter());

                return Task.FromResult(response);
            }

            if (request.RequestUri.AbsoluteUri.EndsWith("jwks"))
            {
                var webKeys = new List<JsonWebKeyDto>();

                var cert64 = Convert.ToBase64String(_signingCertificate.RawData);
                var thumbprint = Base64Url.Encode(_signingCertificate.GetCertHash());
                var key = _signingCertificate.PublicKey.Key as RSACryptoServiceProvider;
                var parameters = key.ExportParameters(false);
                var exponent = Base64Url.Encode(parameters.Exponent);
                var modulus = Base64Url.Encode(parameters.Modulus);

                var webKey = new JsonWebKeyDto
                {
                    kty = "RSA",
                    use = "sig",
                    kid = thumbprint,
                    x5t = thumbprint,
                    e = exponent,
                    n = modulus,
                    x5c = new[] { cert64 }
                };

                webKeys.Add(webKey);

                var data = new Dictionary<object, object>
                {
                    { "keys", webKeys }
                };

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ObjectContent<Dictionary<object, object>>(data, new JsonMediaTypeFormatter());

                return Task.FromResult(response);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private class JsonWebKeyDto
        {
            public string kty { get; set; }
            public string use { get; set; }
            public string kid { get; set; }
            public string x5t { get; set; }
            public string e { get; set; }
            public string n { get; set; }
            public string[] x5c { get; set; }
        }
    }
}