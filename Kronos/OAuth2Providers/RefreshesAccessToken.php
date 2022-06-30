<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;

trait RefreshesAccessToken
{
    /**
     * @throws IdentityProviderException
     * @throws InvalidRefreshTokenException
     */
    public function getAccessTokenByRefreshToken(string $refreshToken, array $options = []): AccessTokenInterface
    {
        if (empty($refreshToken)) {
            throw new InvalidRefreshTokenException($refreshToken);
        }

        return $this->provider->getAccessToken('refresh_token', array_merge([
            'refresh_token' => $refreshToken,
        ], $options));
    }
}
