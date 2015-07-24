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
    public class IdentityServerTokenAuthenticationOptions : AuthenticationOptions
    {
        public IdentityServerTokenAuthenticationOptions() : base("Bearer")
        {
            NameClaimType = "name";
            RoleClaimType = "role";

            ValidationMode = ValidationMode.Both;

            RequiredScopes = Enumerable.Empty<string>();

            ValidationResultCacheDuration = TimeSpan.FromMinutes(5);
        }

        public string Authority { get; set; }

        public ValidationMode ValidationMode { get; set; }

        public WebRequestHandler BackchannelHttpHandler { get; set; }
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public string NameClaimType { get; set; }
        public string RoleClaimType { get; set; }

        public IOAuthBearerAuthenticationProvider TokenProvider { get; set; }

        public TimeSpan ValidationResultCacheDuration { get; set; }

        public bool EnableValidationResultCache { get; set; }

        public IValidationResultCache ValidationResultCache { get; set; }

        public IEnumerable<string> RequiredScopes { get; set; }
    }
}