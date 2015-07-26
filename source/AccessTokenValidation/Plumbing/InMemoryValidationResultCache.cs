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
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// In-memory cache for validation results
    /// </summary>
    public class InMemoryValidationResultCache : IValidationResultCache
    {
        private readonly IdentityServerBearerTokenAuthenticationOptions _options;
        private readonly ICache _cache;
        private readonly IClock _clock;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryValidationResultCache"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        public InMemoryValidationResultCache(IdentityServerBearerTokenAuthenticationOptions options)
            : this(options, new Clock(), new Cache())
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryValidationResultCache"/> class.
        /// </summary>
        /// <param name="options">The options.</param>
        /// <param name="clock">The clock.</param>
        /// <param name="cache">The cache.</param>
        /// <exception cref="System.ArgumentNullException">
        /// clock
        /// or
        /// options
        /// or
        /// cache
        /// </exception>
        public InMemoryValidationResultCache(IdentityServerBearerTokenAuthenticationOptions options, IClock clock, ICache cache)
        {
            if (clock == null) { throw new ArgumentNullException("clock"); }
            if (options == null) { throw new ArgumentNullException("options"); }
            if (cache == null) { throw new ArgumentNullException("cache"); }

            _options = options;
            _cache = cache;
            _clock = clock;
        }

        /// <summary>
        /// Add a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        public Task AddAsync(string token, IEnumerable<Claim> claims)
        {
            var expiryClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Expiration);
            var cacheExpirySetting = _clock.UtcNow.Add(_options.ValidationResultCacheDuration);

            if (expiryClaim != null)
            {
                long epoch;
                if (long.TryParse(expiryClaim.Value, out epoch))
                {
                    var tokenExpiresAt = epoch.ToDateTimeOffsetFromEpoch();

                    if (tokenExpiresAt < cacheExpirySetting)
                    {
                        _cache.Add(token, claims, tokenExpiresAt);
                        return Task.FromResult<object>(null);
                    }
                }
            }

            _cache.Add(token, claims, cacheExpirySetting);

            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Retrieves a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        public Task<IEnumerable<Claim>> GetAsync(string token)
        {
            var result = _cache.Get(token);

            if (result != null)
            {
                return Task.FromResult(result as IEnumerable<Claim>);
            }

            return Task.FromResult<IEnumerable<Claim>>(null);
        }
    }
}