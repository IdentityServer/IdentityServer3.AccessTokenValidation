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

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Interface for caching then token validation result
    /// </summary>
    public interface IValidationResultCache
    {
        /// <summary>
        /// Add a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        Task AddAsync(string token, IEnumerable<Claim> claims);

        /// <summary>
        /// Retrieves a validation result
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        Task<IEnumerable<Claim>> GetAsync(string token);
    }
}