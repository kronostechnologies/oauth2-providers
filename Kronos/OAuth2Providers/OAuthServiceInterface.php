<?php

namespace Kronos\OAuth2Providers;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;

/**
 * @template R of ResourceOwnerInterface
 */
interface OAuthServiceInterface
{
    /**
     * @return R
     */
    public function getResourceOwner(AccessToken $accessToken): ResourceOwnerInterface;

    public function getAccessTokenByAuthorizationCode(string $code, array $options = []): AccessTokenInterface;

    public function getAuthorizationUrl(array $options = []): string;

    public function getState(): string;

    public function validateState(string $state): bool;
}
