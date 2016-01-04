using System.Collections.Generic;

namespace IdentityServer3.AccessTokenValidation
{
    public class ScopeRequirementOptions
    {
        public string AuthenticationType { get; set; }
        public IEnumerable<string> RequiredScopes { get; set; }
    }
}