<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

interface IdTokenFactoryInterface
{

    /**
     * IdTokenFactoryInterface constructor.
     *
     * @param IdTokenParser|null $idTokenParser
     * @param IdTokenValidator|null $idTokenValidator
     */
    public function __construct(IdTokenParser $idTokenParser, IdTokenValidator $idTokenValidator);

    /**
     * Creates an instance of IdTokenInterface
     *
     * @param $idTokenString
     * @param $keys
     * @param $clientId
     * @param $issuer
     * @param null $userIdKey
     * @return IdTokenInterface
     */
    public function createIdToken($idTokenString, $keys, $clientId, $issuer, $userIdKey): IdTokenInterface;
}
