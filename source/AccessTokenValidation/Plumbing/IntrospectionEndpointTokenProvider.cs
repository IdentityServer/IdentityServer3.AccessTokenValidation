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

using IdentityModel.Client;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityServer3.AccessTokenValidation
{
    internal class IntrospectionEndpointTokenProvider : AuthenticationTokenProvider
    {
        private readonly IntrospectionClient _client;
        private readonly IdentityServerBearerTokenAuthenticationOptions _options;
        private readonly ILogger _logger;

        public IntrospectionEndpointTokenProvider(IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);

            if (string.IsNullOrWhiteSpace(options.Authority))
            {
                throw new Exception("Authority must be set to use validation endpoint.");
            }

            var baseAddress = options.Authority.EnsureTrailingSlash();
            baseAddress += "connect/introspect";
            var introspectionEndpoint = baseAddress;

            var handler = options.IntrospectionHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Invalid certificate validator");
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            if (!string.IsNullOrEmpty(options.ClientId))
            {
                _client = new IntrospectionClient(
                    introspectionEndpoint, 
                    options.ClientId, 
                    options.ClientSecret,
                    handler);
            }
            else
            {
                _client = new IntrospectionClient(
                    introspectionEndpoint,
                    innerHttpMessageHandler: handler);
            }

            _options = options;
        }

        public override async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            if (_options.EnableValidationResultCache)
            {
                var cachedClaims = await _options.ValidationResultCache.GetAsync(context.Token);
                if (cachedClaims != null)
                {
                    SetAuthenticationTicket(context, cachedClaims);
                    return;
                }
            }

            IntrospectionResponse response;
            try
            {
                response = await _client.SendAsync(new IntrospectionRequest { Token = context.Token });
                if (response.IsError)
                {
                    _logger.WriteError("Error returned from introspection endpoint: " + response.Error);
                    return;
                }
                if (!response.IsActive)
                {
                    _logger.WriteVerbose("Inactive token: " + context.Token);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.WriteError("Exception while contacting introspection endpoint: " + ex.ToString());
                return;
            }

            var claims = new List<Claim>();
            foreach (var claim in response.Claims)
            {
                if (!string.Equals(claim.Item1, "active", StringComparison.Ordinal))
                {
                    claims.Add(new Claim(claim.Item1, claim.Item2));
                }
            }
            
            if (_options.EnableValidationResultCache)
            {
                await _options.ValidationResultCache.AddAsync(context.Token, claims);
            }

            SetAuthenticationTicket(context, claims);
        }

        private void SetAuthenticationTicket(AuthenticationTokenReceiveContext context, IEnumerable<Claim> claims)
        {
            var id = new ClaimsIdentity(
                            claims,
                            _options.AuthenticationType,
                            _options.NameClaimType,
                            _options.RoleClaimType);

            context.SetTicket(new AuthenticationTicket(id, new AuthenticationProperties()));
        }
    }
}