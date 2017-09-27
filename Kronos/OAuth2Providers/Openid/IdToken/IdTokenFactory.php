<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

class IdTokenFactory {

	/**
	 * @var IdTokenParser
	 */
	protected $idTokenParser;

	/**
	 * @var IdTokenValidator
	 */
	protected $idTokenValidator;

	public function __construct(IdTokenParser $idTokenParser = null, IdTokenValidator $idTokenValidator = null) {
		$this->idTokenParser = $idTokenParser ?: new IdTokenParser();
		$this->idTokenValidator = $idTokenValidator ?: new IdTokenValidator();
	}

	public function createIdToken($idTokenString, $keys, $clientId, $issuer, $nonce, $userIdKey = null) {
		$idTokenClaims = $this->idTokenParser->parseIdToken($idTokenString, $keys);
		$this->idTokenValidator->validateIdTokenClaims($idTokenClaims, $clientId, $issuer, $nonce);

		return new IdToken($idTokenClaims, $userIdKey);
	}
}