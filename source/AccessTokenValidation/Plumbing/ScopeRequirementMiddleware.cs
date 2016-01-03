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
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AppFunc = System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Middleware to check for scope claims in access token
    /// </summary>
    public class ScopeRequirementMiddleware
    {
        private readonly AppFunc _next;
        private readonly ScopeRequirementOptions _options;
        
        /// <summary>
        /// Initializes a new instance of the <see cref="ScopeRequirementMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next midleware.</param>
        /// <param name="options">The options.</param>
        public ScopeRequirementMiddleware(AppFunc next, ScopeRequirementOptions options)
        {
            _next = next;
            _options = options;
        }

        /// <summary>
        /// Invokes the middleware.
        /// </summary>
        /// <param name="env">The OWIN environment.</param>
        /// <returns></returns>
        public async Task Invoke(IDictionary<string, object> env)
        {
            var context = new OwinContext(env);

            // if no token was sent - no need to validate scopes
            ClaimsPrincipal principal = null;

            if (!string.IsNullOrWhiteSpace(_options.AuthenticationType))
            {
                var result = await context.Authentication.AuthenticateAsync(_options.AuthenticationType);
                if (result != null && result.Identity != null)
                {
                    principal = new ClaimsPrincipal(result.Identity);
                }
            }
            else
            {
                principal = context.Authentication.User;
            }

            if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated)
            {
                await _next(env);
                return;
            }

            if (ScopesFound(context))
            {
                await _next(env);
                return;
            }

            context.Response.StatusCode = 403;
            context.Response.Headers.Add("WWW-Authenticate", new[] { "Bearer error=\"insufficient_scope\"" });

            EmitCorsResponseHeaders(env);
        }

        private void EmitCorsResponseHeaders(IDictionary<string, object> env)
        {
            var ctx = new OwinContext(env);
            string[] values;

            if (ctx.Request.Headers.TryGetValue("Origin", out values))
            {
                ctx.Response.Headers.Add("Access-Control-Allow-Origin", values);
                ctx.Response.Headers.Add("Access-Control-Expose-Headers", new string[] { "WWW-Authenticate" });
            }

            if (ctx.Request.Headers.TryGetValue("Access-Control-Request-Method", out values))
            {
                ctx.Response.Headers.Add("Access-Control-Allow-Method", values);
            }

            if (ctx.Request.Headers.TryGetValue("Access-Control-Request-Headers", out values))
            {
                ctx.Response.Headers.Add("Access-Control-Allow-Headers", values);
            }
        }

        private bool ScopesFound(OwinContext context)
        {
            var scopeClaims = context.Authentication.User.FindAll("scope");

            if (scopeClaims == null || !scopeClaims.Any())
            {
                return false;
            }

            foreach (var scope in scopeClaims)
            {
                if (_options.RequiredScopes.Contains(scope.Value, StringComparer.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }
}