<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use InvalidArgumentException;

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
		$this->idTokenParser = empty($idTokenParser) ? new IdTokenParser() : $idTokenParser;
		$this->idTokenValidator = empty($idTokenValidator) ? new IdTokenValidator() : $idTokenValidator;
	}

	public function createIdToken($idTokenString, $keys, $clientId, $issuer, $nonce, $userIdKey) {
		$idTokenClaims = $this->idTokenParser->parseIdToken($idTokenString, $keys);
		$this->idTokenValidator->validateIdTokenClaims($idTokenClaims, $clientId, $issuer, $nonce);

		return new IdToken($idTokenClaims, $userIdKey);
	}
}