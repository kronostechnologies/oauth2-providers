# oauth2-providers
Equisoft OAuth2 providers for https://github.com/thephpleague/oauth2-client

- Auth0
- Google
- Microsoft
- OpenId

### Note for the Microsoft provider
The Microsoft provider is able to connect to both version 1 and 2 of the Identity Platform (Azure).
To use a specific version, the provider must be instantiated with the appropriate option:
```php
$provider = new MicrosoftProvider([
    'version' => MicrosoftProvider::VERSION_2_0,
]);
```

Also, for the `email` claim to be available in the Resource Owner, the optional `email` scope must
be included. It can be added using the `scopes` option during instanciation, or it can be part of
the options passed during subsequent token requests
(https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens).

For additional configuration options, check the documentation of the provider:

https://github.com/thenetworg/oauth2-azure
