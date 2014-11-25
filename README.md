Thinktecture.IdentityServer.v3.AccessTokenValidation
====================================================

OWIN Middleware to validate access tokens from IdentityServer v3.

You can either validate the tokens locally (JWTs only) or use the IdentityServer's access token validation endpoint (JWTs and reference tokens).

```csharp
app.UseIdentityServerBearerTokenAuthentication(new UseIdentityServerBearerTokenAuthentication
    {
        Authority = "https://identity.thinktecture.com"
    });
```

The middleware can also do the scope validation in one go.

```csharp
app.UseIdentityServerBearerTokenAuthentication(new UseIdentityServerBearerTokenAuthentication
    {
        Authority = "https://identity.thinktecture.com",
        RequiredScopes = new[] { "api1", "api2" }
    });
```
