<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

interface IdTokenInterface extends \JsonSerializable
{
    /**
     * Constructs an id token.
     *
     * @param array $idTokenClaims
     * @param string $userIdKey
     */
    public function __construct(array $idTokenClaims, $userIdKey);

    /**
     * Returns this token's claims.
     *
     * @return array
     */
    public function getClaims();

    /**
     * Returns this token's 'user id', corresponding to the claim identified at initialization time by the provider.
     *
     * @return mixed
     */
    public function getUserId();
}
