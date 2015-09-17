using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityServer3.AccessTokenValidation;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class DynamicBoth
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            Authority = "https://discodoc",
            ValidationMode = ValidationMode.Both
        };

        [Fact]
        public async Task No_Token_Sent()
        {
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task JWT_Invalid_Token_Sent()
        {
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("in.valid");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task JWT_Sent_No_Scope_No_ScopeRequirements()
        {
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(TokenFactory.CreateToken());

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task JWT_Sent_No_Scope_Api1_ScopeRequirements()
        {
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();
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
            _options.BackchannelHttpHandler = new DiscoveryEndpointHandler();
            _options.RequiredScopes = new[] { TokenFactory.Api1Scope };

            var client = PipelineFactory.CreateHttpClient(_options);
            var token = TokenFactory.CreateTokenString(
                TokenFactory.CreateToken(scope: new[] { TokenFactory.Api1Scope }));

            client.SetBearerToken(token);

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }
}