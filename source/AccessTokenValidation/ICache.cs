using System;

namespace Thinktecture.IdentityServer.v3.AccessTokenValidation
{
	public interface ICache
	{
		bool Add(string key, object value, DateTimeOffset absoluteExpiration);

		object Get(string key);
	}
}