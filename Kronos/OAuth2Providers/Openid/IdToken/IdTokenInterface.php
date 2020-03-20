<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

interface IdTokenInterface
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

    /**
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize();
}
