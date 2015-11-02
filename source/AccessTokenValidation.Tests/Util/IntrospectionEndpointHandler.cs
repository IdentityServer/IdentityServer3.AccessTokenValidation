using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class IntrospectionEndpointHandler : WebRequestHandler
    {
        private readonly Behavior _behavior;

        public enum Behavior
        {
            Active, 
            Inactive,
            Unauthorized
        }

        public IntrospectionEndpointHandler(Behavior behavior)
        {
            _behavior = behavior;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_behavior == Behavior.Unauthorized)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Active)
            {
                var responseObject = new Dictionary<object, object>
                {
                    { "active", true }
                };

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ObjectContent<Dictionary<object, object>>(
                    responseObject, new JsonMediaTypeFormatter());

                return Task.FromResult(response);
            }
            if (_behavior == Behavior.Inactive)
            {
                var responseObject = new Dictionary<object, object>
                {
                    { "active", false }
                };

                var response = new HttpResponseMessage(HttpStatusCode.OK);
                response.Content = new ObjectContent<Dictionary<object, object>>(
                    responseObject, new JsonMediaTypeFormatter());

                return Task.FromResult(response);
            }

            throw new NotImplementedException();
        }
    }
}