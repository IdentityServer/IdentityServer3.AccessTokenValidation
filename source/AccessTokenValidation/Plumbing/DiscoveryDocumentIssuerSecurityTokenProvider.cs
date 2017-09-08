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

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using IdentityServer3.AccessTokenValidation.Plumbing;

namespace IdentityServer3.AccessTokenValidation
{
    internal class DiscoveryDocumentIssuerSecurityTokenProvider : IIssuerSecurityTokenProvider
    {
        private readonly ReaderWriterLockSlim _synclock = new ReaderWriterLockSlim();
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly ILogger _logger;
        private string _issuer;
        private IEnumerable<SecurityToken> _tokens;

        public DiscoveryDocumentIssuerSecurityTokenProvider(string discoveryEndpoint, IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);

            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("The back channel handler must derive from WebRequestHandler in order to use a certificate validator");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            _configurationManager = new AdapterConfigurationManager(new ConfigurationManager<OpenIdConnectConfiguration>(discoveryEndpoint, new HttpClient(handler))
            {
                AutomaticRefreshInterval = options.AutomaticRefreshInterval
            });

            if (!options.DelayLoadMetadata)
            {
                RetrieveMetadata();
            }
        }

        /// <summary>
        /// Gets the issuer the credentials are for.
        /// </summary>
        /// <value>
        /// The issuer the credentials are for.
        /// </value>
        public string Issuer
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _issuer;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <value>
        /// The identity server default audience
        /// </value>
        public string Audience
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    var issuer = _issuer.EnsureTrailingSlash();
                    return issuer + "resources";
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <summary>
        /// Gets all known security tokens.
        /// </summary>
        /// <value>
        /// All known security tokens.
        /// </value>
        public IEnumerable<SecurityToken> SecurityTokens
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _tokens;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        private void RetrieveMetadata()
        {
            _synclock.EnterWriteLock();
            try
            {
                var result = AsyncHelper.RunSync(async () => await _configurationManager.GetConfigurationAsync(CancellationToken.None));

                if (result.JsonWebKeySet == null)
                {
                    _logger.WriteError("Discovery document has no configured signing key. aborting.");
                    throw new InvalidOperationException("Discovery document has no configured signing key. aborting.");
                }

                var tokens = new List<SecurityToken>();
                foreach (var key in result.JsonWebKeySet.Keys)
                {
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(key.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(key.N)
                    });

                    tokens.Add(new RsaSecurityToken(rsa, key.Kid));
                }

                _issuer = result.Issuer;
                _tokens = tokens;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Error contacting discovery endpoint: " + ex.ToString());
                throw;
            }
            finally
            {
                _synclock.ExitWriteLock();
            }
        }
    }
}