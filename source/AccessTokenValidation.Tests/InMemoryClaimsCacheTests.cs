using System;
using Thinktecture.IdentityServer.v3.AccessTokenValidation;
using Xunit;

namespace AccessTokenValidation.Tests
{
	public class InMemoryClaimsCacheTests
	{
		[Fact]
        public void InvokingConstructor_WithoutSpecifyingIClock_ShouldNotError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			new InMemoryClaimsCache(options);
		}

		[Fact]
        public void InvokingConstructor_WithNullIClock_ShouldError() 
		{
			var options = new IdentityServerBearerTokenAuthenticationOptions();			

			Assert.Throws<ArgumentNullException>(() => new InMemoryClaimsCache(options, null));
		}
	}
}