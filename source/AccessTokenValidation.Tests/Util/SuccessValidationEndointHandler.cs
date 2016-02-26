using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Threading;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class SuccessValidationEndointHandler : HttpMessageHandler
    {
        IEnumerable<Tuple<object, object>> _additionalClaims;

        public SuccessValidationEndointHandler(IEnumerable<Tuple<object, object>> additionalClaims = null)
        {
            _additionalClaims = additionalClaims;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);

            var responseObject = new Dictionary<object, object>
            { 
                { "sub", 123 }
            };

            if (_additionalClaims != null)
            {
                foreach (var item in _additionalClaims)
                {
                    responseObject.Add(item.Item1, item.Item2);
                }
            }

            response.Content = new ObjectContent<Dictionary<object, object>>(
                responseObject, new JsonMediaTypeFormatter());

            return Task.FromResult(response);
        }
    }
}