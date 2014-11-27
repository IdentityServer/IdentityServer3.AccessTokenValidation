using System;
using System.Security.Claims;
using Moq;
using Thinktecture.IdentityServer.v3.AccessTokenValidation;
using Xunit;

namespace AccessTokenValidation.Tests
{
	public class InMemoryClaimsCacheTests
	{
        const string Category = "InMemoryClaimsCache";

		[Fact]
        [Trait("Category", Category)]
        public void InvokingConstructor_SpecifyingOnlyOptions_ShouldNotError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			new InMemoryClaimsCache(options);
		}

		[Fact]
        [Trait("Category", Category)]
        public void InvokingConstructor_WithNullIClock_ShouldError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			Assert.Throws<ArgumentNullException>(() => new InMemoryClaimsCache(options, null, new Cache()));
		}

		[Fact]
        [Trait("Category", Category)]
        public void WhenTokenExpiryClaimExpiresBeforeClaimsCacheDuration_CacheExpiry_ShouldUseTokenExpiryClaim() {
			var now = DateTime.Now;
			var cache = Mock.Of<ICache>();
			var clock = Mock.Of<IClock>(c => c.UtcNow == now);
			var token = "foo";

			// test-specific
			// token expires in 1 min, cache expiry is 5 min
			var expiryClaimValue = clock.UtcNow.AddMinutes(1).ToEpochTime();
			var options = new IdentityServerBearerTokenAuthenticationOptions
				{
					ClaimsCacheDuration = TimeSpan.FromMinutes(5)
				};

			var claims = new[] {new Claim("bar","baz"), new Claim(ClaimTypes.Expiration,expiryClaimValue.ToString()) };
			var sut = new InMemoryClaimsCache(options, clock, cache);
			var expectedCacheExpiry = expiryClaimValue.ToDateTimeOffsetFromEpoch();
			DebugToConsole(now, expiryClaimValue, options, expectedCacheExpiry);

			// act
			sut.AddAsync(token, claims);

			Mock.Get(cache).Verify(c => 
				c.Add(It.IsAny<string>(), It.IsAny<object>(), It.Is<DateTimeOffset>(d => d == expectedCacheExpiry)));
		}

		[Fact]
        [Trait("Category", Category)]
        public void WhenTokenExpiryClaimExpiresAfterClaimsCacheDuration_CacheExpiry_ShouldUseClaimsCacheDuration() {
			var now = DateTime.Now;
			var cache = Mock.Of<ICache>();
			var clock = Mock.Of<IClock>(c => c.UtcNow == now);
			var token = "foo";

			// test-specific
			// token expires in 10 min, cache expiry is 5 min
			var expiryClaimValue = clock.UtcNow.AddMinutes(10).ToEpochTime();
			var options = new IdentityServerBearerTokenAuthenticationOptions
				{
					ClaimsCacheDuration = TimeSpan.FromMinutes(5)
				};

			var claims = new[] {new Claim("bar","baz"), new Claim(ClaimTypes.Expiration,expiryClaimValue.ToString()) };
			var sut = new InMemoryClaimsCache(options, clock, cache);
			var expectedCacheExpiry = clock.UtcNow.Add(options.ClaimsCacheDuration);
			DebugToConsole(now, expiryClaimValue, options, expectedCacheExpiry);

			// act
			sut.AddAsync(token, claims);

			Mock.Get(cache).Verify(c => 
				c.Add(It.IsAny<string>(), It.IsAny<object>(), It.Is<DateTimeOffset>(d => d == expectedCacheExpiry)));
		}

		static void DebugToConsole(DateTime now, long expiryClaimValue, IdentityServerBearerTokenAuthenticationOptions options, DateTimeOffset expectedCacheExpiry) {
			Console.WriteLine("now: {0}", now);
			Console.WriteLine("expiry claim value: {0}", expiryClaimValue.ToDateTimeOffsetFromEpoch());
			Console.WriteLine("claims cache duration: {0}", options.ClaimsCacheDuration);
			Console.WriteLine("expected cache expiry: {0}", expectedCacheExpiry);
		}
	}
}