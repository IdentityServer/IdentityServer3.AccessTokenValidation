using System.Collections.Generic;

namespace IdentityServer3.AccessTokenValidation
{
    /// <summary>
    /// Options for validating scope claims
    /// </summary>
    public class ScopeRequirementOptions
    {
        /// <summary>
        /// Specifies which authentication type should be used (uses primary identity if empty)
        /// </summary>
        public string AuthenticationType { get; set; }

        /// <summary>
        /// Specifies the accepted scope values
        /// </summary>
        public IEnumerable<string> RequiredScopes { get; set; }
    }
}