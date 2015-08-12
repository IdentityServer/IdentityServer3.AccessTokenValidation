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

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Configures identity server token validation
    /// </summary>
    public class IdentityServerBearerTokenAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityServerBearerTokenAuthenticationOptions"/> class.
        /// </summary>
        public IdentityServerBearerTokenAuthenticationOptions() : base("Bearer")
        {
            NameClaimType = "name";
            RoleClaimType = "role";

            ValidationMode = ValidationMode.Both;
            RequiredScopes = Enumerable.Empty<string>();
            ValidationResultCacheDuration = TimeSpan.FromMinutes(5);
        }

        /// <summary>
        /// Gets or sets the base address of identity server (required)
        /// </summary>
        /// <value>
        /// The authority.
        /// </value>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets the validation mode.
        /// </summary>
        /// <value>
        /// The validation mode.
        /// </value>
        public ValidationMode ValidationMode { get; set; }

        /// <summary>
        /// Gets or sets the backchannel HTTP handler.
        /// </summary>
        /// <value>
        /// The backchannel HTTP handler.
        /// </value>
        public WebRequestHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Gets or sets the backchannel certificate validator.
        /// </summary>
        /// <value>
        /// The backchannel certificate validator.
        /// </value>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Gets or sets the type of the name claim.
        /// </summary>
        /// <value>
        /// The type of the name claim.
        /// </value>
        public string NameClaimType { get; set; }

        /// <summary>
        /// Gets or sets the type of the role claim.
        /// </summary>
        /// <value>
        /// The type of the role claim.
        /// </value>
        public string RoleClaimType { get; set; }

        /// <summary>
        /// Gets or sets the token provider.
        /// </summary>
        /// <value>
        /// The token provider.
        /// </value>
        public IOAuthBearerAuthenticationProvider TokenProvider { get; set; }

        /// <summary>
        /// Gets or sets the duration of the validation result cache.
        /// </summary>
        /// <value>
        /// The duration of the validation result cache.
        /// </value>
        public TimeSpan ValidationResultCacheDuration { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to enable validation result caching.
        /// </summary>
        /// <value>
        /// <c>true</c> if [enable validation result cache]; otherwise, <c>false</c>.
        /// </value>
        public bool EnableValidationResultCache { get; set; }

        /// <summary>
        /// Gets or sets the validation result cache.
        /// </summary>
        /// <value>
        /// The validation result cache.
        /// </value>
        public IValidationResultCache ValidationResultCache { get; set; }

        /// <summary>
        /// Gets or sets the required scopes.
        /// </summary>
        /// <value>
        /// The required scopes.
        /// </value>
        public IEnumerable<string> RequiredScopes { get; set; }
    }
}