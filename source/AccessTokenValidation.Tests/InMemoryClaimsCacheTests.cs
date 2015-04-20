using Moq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using IdentityModel.Extensions;
using IdentityServer3.AccessTokenValidation;
using Xunit;

namespace AccessTokenValidation.Tests
{
	public class InMemoryClaimsCacheTests
	{
        const string Category = "InMemoryClaimsCache";
		protected double ExpiryClaimSaysTokenExpiresInMinutes;
		protected double CacheEvictsTokensAfterMinutes;
		IdentityServerBearerTokenAuthenticationOptions _options;
		ICache _cache;
		IClock _clock;
		protected IEnumerable<Claim> Claims;
		string token = "foo";
		protected DateTimeOffset ExpectedCacheExpiry;
		protected DateTimeOffset ExpiryClaimSaysTokenExpiresAt;
		protected DateTimeOffset CacheExpiryEvictsTokenAt;
		protected InMemoryValidationResultCache Sut;

		[Fact]
        [Trait("Category", Category)]
        public void InvokingConstructor_WithOptionsOnly_ShouldNotError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			new InMemoryValidationResultCache(options);
		}

		[Fact]
        [Trait("Category", Category)]
        public void InvokingConstructor_WithNullIClock_ShouldError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			Assert.Throws<ArgumentNullException>(() => new InMemoryValidationResultCache(options, null, new Cache()));
		}

		[Fact]
        [Trait("Category", Category)]
        public void WhenTokenExpiryClaimExpiresBeforeClaimsCacheDuration_CacheExpiry_ShouldUseTokenExpiryClaim() {
			ExpiryClaimSaysTokenExpiresInMinutes = 1;
			CacheEvictsTokensAfterMinutes = 5;
			Arrange(() =>
				{
					// mimic the DateTimeOffset rounding that happens via serialisation/deserialisation in the actual implementation
					ExpectedCacheExpiry = ExpiryClaimSaysTokenExpiresAt.ToEpochTime().ToDateTimeOffsetFromEpoch(); 
				});

			// act
			Sut.AddAsync(token, Claims);

			Mock.Get(_cache).Verify(c => 
				c.Add(It.IsAny<string>(), It.IsAny<object>(), It.Is<DateTimeOffset>(d => d == ExpectedCacheExpiry)));
		}

		[Fact]
        [Trait("Category", Category)]
        public void WhenTokenExpiryClaimExpiresAfterClaimsCacheDuration_CacheExpiry_ShouldUseClaimsCacheDuration() {
			ExpiryClaimSaysTokenExpiresInMinutes = 10;
			CacheEvictsTokensAfterMinutes = 5;
			Arrange(() => ExpectedCacheExpiry = CacheExpiryEvictsTokenAt);

			// act
			Sut.AddAsync(token, Claims);

			Mock.Get(_cache).Verify(c => 
				c.Add(It.IsAny<string>(), It.IsAny<object>(), It.Is<DateTimeOffset>(d => d == ExpectedCacheExpiry)));
		}

		void Arrange(Action specifyExpectedCacheExpiry) {
			_cache = Mock.Of<ICache>();
			_clock = Mock.Of<IClock>(c => c.UtcNow == DateTimeOffset.Now);
			_options = new IdentityServerBearerTokenAuthenticationOptions
				{
					ValidationResultCacheDuration = TimeSpan.FromMinutes(CacheEvictsTokensAfterMinutes)
				};
			ExpiryClaimSaysTokenExpiresAt = _clock.UtcNow.AddMinutes(ExpiryClaimSaysTokenExpiresInMinutes);
			CacheExpiryEvictsTokenAt = _clock.UtcNow.Add(_options.ValidationResultCacheDuration);
			
			// setup claims to include expiry claim
			Claims = new[] {new Claim("bar","baz"), new Claim(ClaimTypes.Expiration,ExpiryClaimSaysTokenExpiresAt.ToEpochTime().ToString()) };

			specifyExpectedCacheExpiry();

			DebugToConsole(DateTime.Now, ExpiryClaimSaysTokenExpiresAt,  _options, CacheExpiryEvictsTokenAt, ExpectedCacheExpiry);
			Sut = new InMemoryValidationResultCache(_options, _clock, _cache);
		}

		static void DebugToConsole(DateTime now, DateTimeOffset expiryClaimSaysTokenExpiresAt, IdentityServerBearerTokenAuthenticationOptions options, DateTimeOffset cacheExpiryEvictsTokenAt, DateTimeOffset expectedCacheExpiry) {
			Console.WriteLine("now: {0}", now);
			Console.WriteLine("expiry claim says token expires at: {0}", expiryClaimSaysTokenExpiresAt);
			Console.WriteLine("claims cache duration: {0}", options.ValidationResultCacheDuration);
			Console.WriteLine("cache expiry evicts token at: {0}", cacheExpiryEvictsTokenAt);
			Console.WriteLine("expected cache expiry: {0}", expectedCacheExpiry);
		}
	}
}