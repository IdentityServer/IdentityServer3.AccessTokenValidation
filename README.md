Thinktecture.IdentityServer.v3.AccessTokenValidation
====================================================

[![Build status](https://ci.appveyor.com/api/projects/status/2qk9c4dxea9g801e?svg=true)](https://ci.appveyor.com/project/leastprivilege/thinktecture-identityserver-v3-accesstokenvalidati)


OWIN Middleware to validate access tokens from IdentityServer v3.

You can either validate the tokens locally (JWTs only) or use the IdentityServer's access token validation endpoint (JWTs and reference tokens).

```csharp
app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
    {
        Authority = "https://identity.thinktecture.com"
    });
```

The middleware can also do the scope validation in one go.

```csharp
app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
    {
        Authority = "https://identity.thinktecture.com",
        RequiredScopes = new[] { "api1", "api2" }
    });
```
