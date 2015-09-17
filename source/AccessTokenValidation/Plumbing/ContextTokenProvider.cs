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
using System.Threading.Tasks;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Token provider that returns the token already found by the identityserver token middleware
    /// </summary>
    public class ContextTokenProvider : IOAuthBearerAuthenticationProvider
    {
        /// <summary>
        /// Invoked before the <see cref="T:System.Security.Claims.ClaimsIdentity" /> is created. Gives the application an
        /// opportunity to find the identity from a different location, adjust, or reject the token.
        /// </summary>
        /// <param name="context">Contains the token string.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        public Task RequestToken(OAuthRequestTokenContext context)
        {
            context.Token = context.OwinContext.Get<string>("idsrv:tokenvalidation:token");
            return Task.FromResult(0);
        }

        /// <summary>
        /// Called each time a challenge is being sent to the client. By implementing this method the application
        /// may modify the challenge as needed.
        /// </summary>
        /// <param name="context">Contains the default challenge.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public Task ApplyChallenge(OAuthChallengeContext context)
        {
            return Task.FromResult(0);
        }

        /// <summary>
        /// Called each time a request identity has been validated by the middleware. By implementing this method the
        /// application may alter or reject the identity which has arrived with the request.
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="T:System.Security.Claims.ClaimsIdentity" />.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> representing the completed operation.
        /// </returns>
        public Task ValidateIdentity(OAuthValidateIdentityContext context)
        {
            return Task.FromResult(0);
        }
    }
}