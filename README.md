IdentityServer3 - AccessTokenValidation
====================================================

Dev build: [![Build status](https://ci.appveyor.com/api/projects/status/2qk9c4dxea9g801e?svg=true)](https://ci.appveyor.com/project/leastprivilege/thinktecture-identityserver-v3-accesstokenvalidati)
[![Gitter](https://badges.gitter.im/Join Chat.svg)](https://gitter.im/IdentityServer/IdentityServer3?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

OWIN Middleware to validate access tokens from IdentityServer v3.

You can either validate the tokens locally (JWTs only) or use the IdentityServer's access token validation endpoint (JWTs and reference tokens).

```csharp
app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
    {
        Authority = "https://identity.identityserver.io"
    });
```

The middleware can also do the scope validation in one go.

```csharp
app.UseIdentityServerBearerTokenAuthentication(new IdentityServerBearerTokenAuthenticationOptions
    {
        Authority = "https://identity.identityserver.io",
        RequiredScopes = new[] { "api1", "api2" }
    });
```
