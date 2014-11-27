using System;
using System.Runtime.Caching;

namespace Thinktecture.IdentityServer.v3.AccessTokenValidation
{
	public class Cache : ICache
	{
		const string CacheRegionName = "thinktecture.validationCache";
		readonly MemoryCache _cache = new MemoryCache(CacheRegionName);

		public bool Add(string key, object value, DateTimeOffset absoluteExpiration) {
			return _cache.Add(key, value, absoluteExpiration, CacheRegionName);
		}

		public object Get(string key) {
			return _cache.Get(key, CacheRegionName);
		}
	}
}