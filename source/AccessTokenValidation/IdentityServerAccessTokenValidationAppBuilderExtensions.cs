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

using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using System;
using System.IdentityModel.Tokens;
using System.Linq;

namespace Owin
{
    /// <summary>
    /// Extension method for wiring up the access token validation middleware to the OWIN pipeline
    /// </summary>
    public static class IdentityServerAccessTokenValidationAppBuilderExtensions
    {
        /// <summary>
        /// Adds the access token validation middleware to the OWIN pipeline.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentNullException">options</exception>
        public static IAppBuilder UseIdentityServerBearerTokenAuthentication(this IAppBuilder app, IdentityServerBearerTokenAuthenticationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            if (options.ValidationMode == ValidationMode.Local)
            {
                app.UseLocalValidation(options);
            }
            else if (options.ValidationMode == ValidationMode.ValidationEndpoint)
            {
                app.UseValidationEndpoint(options);
            }

            if (options.RequiredScopes.Any())
            {
                app.Use<ScopeRequirementMiddleware>(options.RequiredScopes);
            }

            return app;
        }

        internal static void UseLocalValidation(this IAppBuilder app, IdentityServerBearerTokenAuthenticationOptions options)
        {
            JwtFormat tokenFormat = null;

            // use discovery document to fully configure middleware
            if (!string.IsNullOrEmpty(options.Authority))
            {
                var discoveryEndpoint = options.Authority.EnsureTrailingSlash();
                discoveryEndpoint += ".well-known/openid-configuration";

                var issuerProvider = new CachingDiscoveryIssuerSecurityTokenProvider(
                    discoveryEndpoint,
                    options);

                if (options.TokenValidationParameters != null)
                {
                    tokenFormat = new JwtFormat(options.TokenValidationParameters, issuerProvider);
                }
                else
                {
                    var valParams = new TokenValidationParameters
                    {
                        ValidAudience = issuerProvider.Audience,
                        NameClaimType = options.NameClaimType,
                        RoleClaimType = options.RoleClaimType
                    };

                    tokenFormat = new JwtFormat(valParams, issuerProvider);
                }
            }
            // use token validation parameters
            else if (options.TokenValidationParameters != null)
            {
                tokenFormat = new JwtFormat(options.TokenValidationParameters);
            }
            // use simplified manual configuration
            else
            {
                var valParams = new TokenValidationParameters
                {
                    ValidIssuer = options.IssuerName,
                    ValidAudience = options.IssuerName.EnsureTrailingSlash() + "resources",
                    IssuerSigningToken = new X509SecurityToken(options.IssuerCertificate),
                    NameClaimType = options.NameClaimType,
                    RoleClaimType = options.RoleClaimType
                };

                tokenFormat = new JwtFormat(valParams);
            }

            if (options.TokenHandler != null)
            {
                tokenFormat.TokenHandler = options.TokenHandler;
            }

            var bearerOptions = new OAuthBearerAuthenticationOptions
            {
                Provider = options.Provider,
                AccessTokenFormat = tokenFormat,
                AuthenticationMode = options.AuthenticationMode,
                AuthenticationType = options.AuthenticationType,
                Description = options.Description
            };

            app.UseOAuthBearerAuthentication(bearerOptions);
        }

        internal static void UseValidationEndpoint(this IAppBuilder app, IdentityServerBearerTokenAuthenticationOptions options)
        {
            if (options.EnableValidationResultCache)
            {
                if (options.ValidationResultCache == null)
                {
                    options.ValidationResultCache = new InMemoryValidationResultCache(options);
                }
            }

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
            {
                AccessTokenProvider = new ValidationEndpointTokenProvider(options, app.GetLoggerFactory()),
                Provider = options.Provider
            });
        }
    }
}