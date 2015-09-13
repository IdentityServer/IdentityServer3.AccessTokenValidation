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

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Enum for specifying where to validate the access token
    /// </summary>
    public enum ValidationMode
    {
        /// <summary>
        /// Use local validation for JWTs and the validation endpoint for reference tokens
        /// </summary>
        Both,

        /// <summary>
        /// Use local validation oly (only suitable for JWT tokens)
        /// </summary>
        Local,

        /// <summary>
        /// Use the validation endpoint only (works for both JWT and reference tokens)
        /// </summary>
        ValidationEndpoint
    }
}