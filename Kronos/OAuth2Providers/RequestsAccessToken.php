<?php

namespace Kronos\OAuth2Providers;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;

trait RequestsAccessToken
{
    /**
     * @throws IdentityProviderException
     */
    public function getAccessTokenByAuthorizationCode(string $code, array $options = []): AccessTokenInterface
    {
        return $this->provider->getAccessToken('authorization_code', array_merge([
            'code' => $code
        ], $options));
    }
}
