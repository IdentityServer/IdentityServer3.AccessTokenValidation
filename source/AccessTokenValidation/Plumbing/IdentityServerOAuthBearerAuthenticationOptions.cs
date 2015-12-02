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

using Microsoft.Owin.Security.OAuth;
using System;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Options that wraps OAuth2BearerAuthenticationOptions for local and remote token validation
    /// </summary>
    public class IdentityServerOAuthBearerAuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the token provider (set this if the access token is NOT on the authorization header using a Bearer scheme.
        /// </summary>
        /// <value>
        /// The token provider.
        /// </value>
        public IOAuthBearerAuthenticationProvider TokenProvider { get; set; }

        /// <summary>
        /// Gets or sets the local validation options.
        /// </summary>
        /// <value>
        /// The local validation options.
        /// </value>
        public Lazy<OAuthBearerAuthenticationOptions> LocalValidationOptions { get; set; }

        /// <summary>
        /// Gets or sets the endpoint validation options.
        /// </summary>
        /// <value>
        /// The endpoint validation options.
        /// </value>
        public Lazy<OAuthBearerAuthenticationOptions> EndpointValidationOptions { get; set; }
    }
}