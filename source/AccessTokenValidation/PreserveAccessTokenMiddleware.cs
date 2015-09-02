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
    internal class PreserveAccessTokenMiddleware
    {
        private readonly AppFunc _next;

        /// <summary>
        /// Initializes a new instance of the <see cref="PreserveAccessTokenMiddleware"/> class.
        /// </summary>
        /// <param name="next">The next middleware.</param>
        public PreserveAccessTokenMiddleware(AppFunc next)
        {
            _next = next;
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
            var principal = context.Authentication.User;
            if (principal == null || principal.Identity == null || !principal.Identity.IsAuthenticated)
            {
                await _next(env);
                return;
            }

            var token = context.Get<string>("idsrv:tokenvalidation:token");
            if (!string.IsNullOrWhiteSpace(token))
            {
                principal.Identities.First().AddClaim(new Claim("token", token));
            }

            await _next(env);
        }
    }
}