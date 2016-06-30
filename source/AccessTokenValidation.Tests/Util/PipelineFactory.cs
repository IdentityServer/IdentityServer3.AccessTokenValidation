using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin.Builder;
using Microsoft.Owin.Logging;
using Owin;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace AccessTokenValidation.Tests.Util
{
    class PipelineFactory
    {
        public static IAppBuilder Create(IdentityServerBearerTokenAuthenticationOptions options, Action<IAppBuilder> configure)
        {
            IAppBuilder app = new AppBuilder();
            app.SetLoggerFactory(new DiagnosticsLoggerFactory());

            if (configure != null)
            {
                configure(app);
            }

            app.UseIdentityServerBearerTokenAuthentication(options);
            
            app.Use((context, next) =>
            {
                var user = context.Authentication.User;

                if (user == null ||
                    user.Identity == null ||
                    !user.Identity.IsAuthenticated)
                {
                    context.Response.StatusCode = 401;
                }
                else
                {
                    context.Response.StatusCode = 200;
                }

                return Task.FromResult(0);
            });


            return app;
        }

        public static HttpClient CreateHttpClient(IdentityServerBearerTokenAuthenticationOptions options, Action<IAppBuilder> configure = null)
        {
            var app = PipelineFactory.Create(options, configure);
            var handler = new OwinHttpMessageHandler(app.Build());
            var client = new HttpClient(handler);

            return client;
        }
    }
}