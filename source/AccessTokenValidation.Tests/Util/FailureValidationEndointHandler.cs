using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class FailureValidationEndointHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.BadRequest);
            return Task.FromResult(response);
        }
    }
}