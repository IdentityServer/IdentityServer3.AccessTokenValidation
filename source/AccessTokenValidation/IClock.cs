using System;

namespace Thinktecture.IdentityServer.v3.AccessTokenValidation
{
	public interface IClock
	{
		DateTimeOffset UtcNow { get; }
	}
}