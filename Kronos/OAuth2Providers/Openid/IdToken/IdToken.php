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
     * @return mixed
     */
    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->idTokenClaims;
    }
}
