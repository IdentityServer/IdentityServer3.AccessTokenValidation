using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityServer3.AccessTokenValidation;
using Owin;
using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class ResponseHeaders
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            IssuerName = TokenFactory.DefaultIssuer,
            SigningCertificate = new X509Certificate2(Convert.FromBase64String(TokenFactory.DefaultPublicKey)),
            ValidationMode = ValidationMode.Local,
            RequiredScopes = new string[] { TokenFactory.Api2Scope }
        };

        [Fact]
        public async Task WhenCorsHeadersAreAlreadySetOnTheResponse_LeavesThemAsIs()
        {
            var client = PipelineFactory.CreateHttpClient(_options, x =>
            {
                x.Use(async (context, next) =>
                {
                    context.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "ACAO Value" });
                    context.Response.Headers.Add("Access-Control-Allow-Method", new[] { "ACAM Value" });
                    context.Response.Headers.Add("Access-Control-Allow-Headers", new[] { "ACAH Value" });

                    await next();
                });
            });

            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken(scope: new string[] { TokenFactory.Api1Scope }));
            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            var responseHeaders = result.Headers;

            responseHeaders.GetValues("Access-Control-Allow-Origin").Should().BeEquivalentTo("ACAO Value");
            responseHeaders.GetValues("Access-Control-Allow-Method").Should().BeEquivalentTo("ACAM Value");
            responseHeaders.GetValues("Access-Control-Allow-Headers").Should().BeEquivalentTo("ACAH Value");
        }

        [Fact]
        public async Task WhenNoCorsHeadersAreAlreadySetOnTheResponse_SetsThemFromRequestSpecificHeaders()
        {
            var client = PipelineFactory.CreateHttpClient(_options, x =>
            {
                x.Use(async (context, next) =>
                {
                    context.Request.Headers.Add("Origin", new[] { "Origin Value" });
                    context.Request.Headers.Add("Access-Control-Request-Method", new[] { "ACRM Value" });
                    context.Request.Headers.Add("Access-Control-Request-Headers", new[] { "ACRH Value" });

                    await next();
                });
            });

            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken(scope: new string[] { TokenFactory.Api1Scope }));
            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            var responseHeaders = result.Headers;

            responseHeaders.GetValues("Access-Control-Allow-Origin").Should().BeEquivalentTo("Origin Value");
            responseHeaders.GetValues("Access-Control-Expose-Headers").Should().BeEquivalentTo("WWW-Authenticate");
            responseHeaders.GetValues("Access-Control-Allow-Method").Should().BeEquivalentTo("ACRM Value");
            responseHeaders.GetValues("Access-Control-Allow-Headers").Should().BeEquivalentTo("ACRH Value");
        }
    }
}