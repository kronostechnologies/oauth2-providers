<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

class IdTokenFactory implements IdTokenFactoryInterface
{

    public const DEFAULT_USER_ID_KEY = 'sub';

    /**
     * @var IdTokenParser
     */
    protected $idTokenParser;

    /**
     * @var IdTokenValidator
     */
    protected $idTokenValidator;

    /**
     * IdTokenFactory constructor.
     *
     * @param IdTokenParser|null $idTokenParser
     * @param IdTokenValidator|null $idTokenValidator
     */
    public function __construct(IdTokenParser $idTokenParser = null, IdTokenValidator $idTokenValidator = null)
    {
        $this->idTokenParser = $idTokenParser ?: new IdTokenParser();
        $this->idTokenValidator = $idTokenValidator ?: new IdTokenValidator();
    }

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
    public function createIdToken($idTokenString, $keys, $clientId, $issuer, $userIdKey = null): IdTokenInterface
    {
        $idTokenClaims = $this->idTokenParser->parseIdToken($idTokenString, $keys);
        $this->idTokenValidator->validateIdTokenClaims($idTokenClaims, $clientId, $issuer);

        return new IdToken($idTokenClaims, $userIdKey ?? static::DEFAULT_USER_ID_KEY);
    }
}
