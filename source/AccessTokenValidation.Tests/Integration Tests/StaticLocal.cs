using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityServer3.AccessTokenValidation;
using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class StaticLocal
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            IssuerName = TokenFactory.DefaultIssuer,
            SigningCertificate = new X509Certificate2(Convert.FromBase64String(TokenFactory.DefaultPublicKey)),

            ValidationMode = ValidationMode.Local
        };

        [Fact]
        public async Task No_Token_Sent()
        {
            var client = PipelineFactory.CreateHttpClient(_options);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Invalid_Token_Sent()
        {
            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("in.valid");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Token_Sent_No_Scope_No_ScopeRequirements()
        {
            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task Token_Sent_No_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Token_Sent_No_Scope_Api1_Api2_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope, TokenFactory.Api2Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Token_Sent_Api1_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(
                TokenFactory.CreateToken(scope: new[] { TokenFactory.Api1Scope }));

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task Token_Sent_Api2_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(
                TokenFactory.CreateToken(scope: new[] { TokenFactory.Api2Scope }));

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Token_Sent_Api1_Scope_Api1_Api2_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope, TokenFactory.Api2Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(
                TokenFactory.CreateToken(scope: new[] { TokenFactory.Api1Scope }));

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}