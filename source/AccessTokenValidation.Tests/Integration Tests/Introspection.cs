using AccessTokenValidation.Tests.Util;
using FluentAssertions;
using IdentityServer3.AccessTokenValidation;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace AccessTokenValidation.Tests.Integration_Tests
{
    public class Introspection
    {
        IdentityServerBearerTokenAuthenticationOptions _options = new IdentityServerBearerTokenAuthenticationOptions
        {
            Authority = "https://server/with/introspection",
            ValidationMode = ValidationMode.ValidationEndpoint,
            ClientId = "client",
            ClientSecret = "secret"
        };

        [Fact]
        public async Task Unauthorized_Client()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Unauthorized);

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task ActiveToken()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Active);

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task InactiveToken()
        {
            _options.IntrospectionHttpHandler = new IntrospectionEndpointHandler(IntrospectionEndpointHandler.Behavior.Inactive);

            var client = PipelineFactory.CreateHttpClient(_options);
            client.SetBearerToken("sometoken");

            var result = await client.GetAsync("http://test");
            result.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }
    }
}