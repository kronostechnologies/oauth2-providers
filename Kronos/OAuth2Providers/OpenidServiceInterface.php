<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenInterface;

interface OpenidServiceInterface
{

    /**
     * @return string url for hand shake
     */
    public function getAuthorizationUrl();

    /**
     * @param string $code
     * @return array
     */
    public function getTokenByAuthorizationCode($code);

    /**
     * Requests and creates an id token.
     *
     * @param string $idTokenJWT id token received from authorization code exchange
     * @return IdTokenInterface
     */
    public function parseIdToken($idTokenJWT);

    /**
     * @param $accessToken
     * @return array
     */
    public function getUserInfo($accessToken);
}
