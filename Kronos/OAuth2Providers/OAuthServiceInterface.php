<?php

namespace Kronos\OAuth2Providers;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;

interface OAuthServiceInterface
{
    /**
     * Be careful, interface shared with AbstractProvider
     * @param AccessToken $access_token
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(AccessToken $access_token);

    /**
     * @param string $code
     * @param array $options Additional options to pass getAccessToken()
     * @return AccessTokenInterface
     */
    public function getAccessTokenByAuthorizationCode($code, array $options = []): AccessTokenInterface;

    /**
     * @param array $options Additional options
     * @return string url for handshake
     */
    public function getAuthorizationUrl(array $options = []);

    /**
     * @param string $state
     * @return bool
     */
    public function validateSate($state): bool;
}
