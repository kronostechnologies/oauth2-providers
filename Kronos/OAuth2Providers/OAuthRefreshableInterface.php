<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use League\OAuth2\Client\Token\AccessToken;

interface OAuthRefreshableInterface
{

    /**
     * @param string $refresh_token
     * @return AccessToken
     * @throws InvalidRefreshTokenException
     */
    public function retrieveAccessToken($refresh_token);
}
