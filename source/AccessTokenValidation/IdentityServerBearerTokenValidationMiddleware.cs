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

using Microsoft.Owin;
using Microsoft.Owin.Builder;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AppFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace IdentityServer3.AccessTokenValidation
{
    public class IdentityServerBearerTokenValidationMiddleware
    {
        private readonly AppFunc _next;
        private readonly AppFunc _localValidationFunc;
        private readonly AppFunc _endpointValidationFunc;
        private IdentityServerOAuthBearerAuthenticationOptions _options;

        public IdentityServerBearerTokenValidationMiddleware(AppFunc next, IdentityServerOAuthBearerAuthenticationOptions options)
        {
            _next = next;
            _options = options;

            if (options.LocalValidationOptions != null)
            {
                var localBuilder = new AppBuilder();
                localBuilder.UseOAuthBearerAuthentication(options.LocalValidationOptions);
                localBuilder.Run(ctx => next(ctx.Environment));
                _localValidationFunc = localBuilder.Build();
            }

            if (options.EndpointValidationOptions != null)
            {
                var endpointBuilder = new AppBuilder();
                endpointBuilder.Properties["host.AppName"] = "foobar";

                endpointBuilder.UseOAuthBearerAuthentication(options.EndpointValidationOptions);
                endpointBuilder.Run(ctx => next(ctx.Environment));
                _endpointValidationFunc = endpointBuilder.Build();
            }
        }

        public async Task Invoke(IDictionary<string, object> environment)
        {
            var context = new OwinContext(environment);

            var token = await GetTokenAsync(context);

            if (token == null)
            {
                await _next(environment);
                return;
            }

            context.Set("idsrv:tokenvalidation:token", token);


            // seems to be a JWT
            if (token.Contains('.'))
            {
                // see if local validation is setup
                if (_localValidationFunc != null)
                {
                    await _localValidationFunc(environment);
                    return;
                }
                // otherwise use validation endpoint
                if (_endpointValidationFunc != null)
                {
                    await _endpointValidationFunc(environment);
                    return;
                }
            }
            else
            {
                // use validation endpoint
                if (_endpointValidationFunc != null)
                {
                    await _endpointValidationFunc(environment);
                    return;
                }
            }

            await _next(environment);
        }

        private async Task<string> GetTokenAsync(OwinContext context)
        {
            // find token in default location
            string requestToken = null;
            string authorization = context.Request.Headers.Get("Authorization");
            if (!string.IsNullOrEmpty(authorization))
            {
                if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    requestToken = authorization.Substring("Bearer ".Length).Trim();
                }
            }

            // give application opportunity to find from a different location, adjust, or reject token
            if (_options.TokenProvider != null)
            {
                var requestTokenContext = new OAuthRequestTokenContext(context, requestToken);
                await _options.TokenProvider.RequestToken(requestTokenContext);

                // if no token found, no further work possible
                if (string.IsNullOrEmpty(requestTokenContext.Token))
                {
                    return null;
                }

                return requestTokenContext.Token;
            }

            return requestToken;
        }
    }
}