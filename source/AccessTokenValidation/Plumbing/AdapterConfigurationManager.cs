using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;

namespace IdentityServer3.AccessTokenValidation.Plumbing
{
    internal class AdapterConfigurationManager : IConfigurationManager<OpenIdConnectConfiguration>
    {
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _inner;

        public AdapterConfigurationManager(IConfigurationManager<OpenIdConnectConfiguration> inner)
        {
            _inner = inner;
        }

        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancel)
        {
            var res = AsyncHelper.RunSync(() => _inner.GetConfigurationAsync(cancel));
            return Task.FromResult(res);
        }

        public void RequestRefresh()
        {
            return;
        }
    }
}
