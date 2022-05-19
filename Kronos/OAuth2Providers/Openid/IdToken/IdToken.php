<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

class IdToken implements IdTokenInterface
{

    /**
     * @var string
     */
    protected $userIdKey;

    /**
     * @var array
     */
    protected $idTokenClaims;

    /**
     * Constructs an id token.
     *
     * @param array $idTokenClaims
     * @param string $userIdKey
     */
    public function __construct(array $idTokenClaims, $userIdKey)
    {

        $this->idTokenClaims = $idTokenClaims;
        $this->userIdKey = $userIdKey;
    }

    /**
     * Returns this token's claims.
     *
     * @return array
     */
    public function getClaims()
    {
        return $this->idTokenClaims;
    }

    /**
     * Returns this token's 'user id', corresponding to the claim identified at initialization time by the provider.
     *
     * @return mixed
     */
    public function getUserId()
    {
        return $this->idTokenClaims[$this->userIdKey] ?? null;
    }

    /**
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     * @noinspection PhpMissingReturnTypeInspection On peut pas mettre le mixed en php7.4
     * @noinspection PhpHierarchyChecksInspection
     */
    public function jsonSerialize()
    {
        return $this->idTokenClaims;
    }
}
