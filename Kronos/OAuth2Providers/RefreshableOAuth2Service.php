<?php

namespace Kronos\OAuth2Providers;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * @template P of AbstractProvider
 * @template R of ResourceOwnerInterface
 * @template-extends OAuth2Service<P, R>
 */
class RefreshableOAuth2Service extends OAuth2Service implements OAuthRefreshableInterface
{
    use RefreshesAccessToken;
}
