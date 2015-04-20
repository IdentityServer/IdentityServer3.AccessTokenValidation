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
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Options class for configuring the access token validation middleware
    /// </summary>
    public class IdentityServerBearerTokenAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="IdentityServerBearerTokenAuthenticationOptions"/> class.
        /// </summary>
        public IdentityServerBearerTokenAuthenticationOptions() : base("Bearer")
        {
            ValidationMode = ValidationMode.ValidationEndpoint;
            RequiredScopes = Enumerable.Empty<string>();

            ValidationResultCacheDuration = TimeSpan.FromMinutes(5);

            NameClaimType = "name";
            RoleClaimType = "role";
        }

        // common for local and validation endpoint

        /// <summary>
        /// Gets or sets the validation mode (either local for JWT tokens, or using the validation endpoint for both JWT and reference tokens.
        /// </summary>
        /// <value>
        /// The validation mode.
        /// </value>
        public ValidationMode ValidationMode { get; set; }

        /// <summary>
        /// Gets or sets the base adress of IdentityServer - this is used to construct the URLs to the discovery document and the validation endpoint
        /// </summary>
        /// <value>
        /// The authority.
        /// </value>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets one of the required scopes to access the API
        /// </summary>
        /// <value>
        /// The required scopes.
        /// </value>
        public IEnumerable<string> RequiredScopes { get; set; }

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
        /// Gets or sets the name of the issuer (only use if authority is not set).
        /// </summary>
        /// <value>
        /// The name of the issuer.
        /// </value>
        public string IssuerName { get; set; }

        /// <summary>
        /// Gets or sets the issuer certificate (only used if authority is not set).
        /// </summary>
        /// <value>
        /// The issuer certificate.
        /// </value>
        public X509Certificate2 IssuerCertificate { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether the result of the validation endpoint should be cached.
        /// </summary>
        /// <value>
        ///   <c>true</c> if caching should be enabled; otherwise, <c>false</c>.
        /// </value>
        public bool EnableValidationResultCache { get; set; }

        /// <summary>
        /// Gets or sets the claims cache implementation (defaults to in-memory).
        /// </summary>
        /// <value>
        /// The claims cache.
        /// </value>
        public IValidationResultCache ValidationResultCache { get; set; }

        /// <summary>
        /// Specifies for how long the validation results should be cached.
        /// </summary>
        /// <value>
        /// The duration of the claims cache.
        /// </value>
        public TimeSpan ValidationResultCacheDuration { get; set; }

        /// <summary>
        /// Gets or sets the authentication provider.
        /// </summary>
        /// <value>
        /// The provider.
        /// </value>
        public IOAuthBearerAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the a certificate validator to use to validate the metadata endpoint.
        /// </summary>
        /// <value>
        /// The certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with the metadata endpoint.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="TokenValidationParameters"/> used to determine if a token is valid.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; set; }

        /// <summary>
        /// A System.IdentityModel.Tokens.SecurityTokenHandler designed for creating and validating Json Web Tokens.
        /// </summary>
        public JwtSecurityTokenHandler TokenHandler { get; set; }
    }
}