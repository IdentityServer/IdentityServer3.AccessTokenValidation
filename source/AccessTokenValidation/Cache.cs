/*
 * Copyright 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Runtime.Caching;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Cache implementation using System.Runtime.Cachine.MemoryCache
    /// </summary>
	public class Cache : ICache
	{
        const string CacheName = "IdentityServer3.validationCache";
		readonly MemoryCache _cache = new MemoryCache(CacheName);

        /// <summary>
        /// Adds the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="value">The value.</param>
        /// <param name="absoluteExpiration">The absolute expiration.</param>
        /// <returns></returns>
		public bool Add(string key, object value, DateTimeOffset absoluteExpiration) 
        {
			return _cache.Add(key, value, absoluteExpiration);
		}

        /// <summary>
        /// Gets the specified key.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
		public object Get(string key) 
        {
			return _cache.Get(key);
		}
	}
}