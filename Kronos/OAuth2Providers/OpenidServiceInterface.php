<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenInterface;
use Kronos\OAuth2Providers\Openid\OpenIdUser;

/**
 * @template-extends OAuthServiceInterface<OpenIdUser>
 */
interface OpenidServiceInterface extends OAuthServiceInterface
{
    /**
     * Requests and creates an id token.
     *
     * @param string $idTokenJWT id token received from authorization code exchange
     * @return IdTokenInterface
     */
    public function parseIdToken(string $idTokenJWT): IdTokenInterface;
}
