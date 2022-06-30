<?php

namespace Kronos\OAuth2Providers\Storage;

use League\OAuth2\Client\Token\AccessToken;

interface AccessTokenStorageInterface
{
    public function retrieveAccessToken(string $refreshToken): AccessToken;

    public function storeAccessToken(AccessToken $accessToken): void;
}
