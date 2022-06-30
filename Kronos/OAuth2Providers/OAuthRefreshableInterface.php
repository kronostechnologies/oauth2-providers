<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessTokenInterface;

interface OAuthRefreshableInterface
{
    /**
     * @throws IdentityProviderException
     * @throws InvalidRefreshTokenException
     */
    public function getAccessTokenByRefreshToken(string $refreshToken): AccessTokenInterface;
}
