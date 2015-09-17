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
    public class StaticBoth
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            IssuerName = TokenFactory.DefaultIssuer,
            SigningCertificate = new X509Certificate2(Convert.FromBase64String(TokenFactory.DefaultPublicKey)),
            Authority = "https://notused",

            ValidationMode = ValidationMode.Both
        };

        [Fact]
        public async Task No_Token_Sent()
        {
            var client = PipelineFactory.CreateHttpClient(_options);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task JWT_Invalid_Token_Sent()
        {
            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("in.valid");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task JWT_Sent_No_Scope_No_ScopeRequirements()
        {
            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task JWT_Sent_No_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task JWT_Sent_Api1_Scope_Api1_ScopeRequirements()
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
        public async Task Reference_Invalid_Token_Sent()
        {
            _options.BackchannelHttpHandler = new FailureValidationEndointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("invalid");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task Reference_Sent_No_Scope_No_ScopeRequirements()
        {
            _options.BackchannelHttpHandler = new SuccessValidationEndointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("reference");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task Reference_Sent_No_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };
            _options.BackchannelHttpHandler = new SuccessValidationEndointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("reference");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }

        [Fact]
        public async Task Reference_Sent_Api1_Scope_Api1_ScopeRequirements()
        {
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };
            _options.BackchannelHttpHandler = new SuccessValidationEndointHandler(
                new[] { Tuple.Create<object, object>("scope", TokenFactory.Api1Scope) });

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("reference");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}