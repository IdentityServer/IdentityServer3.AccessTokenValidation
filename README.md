Thinktecture.IdentityServer.v3.AccessTokenValidation
====================================================

OWIN Middleware to validate access tokens from IdentityServer v3

IdentityServer v3 supports two types of access token: JWTs and reference tokens.

#### JWTs
These are standard JSON Web Tokens and you don't really need any special middleware to validate them. In fact we are internally using Microsoft's Katana JWT middleware and simply add discovery support on top. So all you need to know is the base address of your IdentityServer v3 installation, the rest is configured dynamically:

```csharp
app.UseIdentityServerJwt(new JwtTokenValidationOptions
    {
        Authority = "https://identity.thinktecture.com"
    });
```

#### Reference tokens
Reference tokens don't contain any data, they are pointers to data that is stored inside IdentityServer v3. You can validate reference tokens using IdSrv's access token validation endpoint. The middleware makes this process easier:

```csharp
app.UseIdentityServerReferenceToken(new ReferenceTokenValidationOptions
    {
        Authority = "https://identity.thinktecture.com"
    });
```
