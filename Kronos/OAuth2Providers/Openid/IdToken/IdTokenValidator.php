<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\SessionBasedHashService;
use RuntimeException;

class IdTokenValidator {

	/**
	 * @var SessionBasedHashService
	 */
	protected $sessionBasedHashService;

	public function __construct(SessionBasedHashService $sessionBasedHashService = null) {
		$this->sessionBasedHashService = empty($sessionBasedHashService) ? new SessionBasedHashService() : $sessionBasedHashService;
	}

	public function validateIdTokenClaims(array $idTokenClaims, $clientId, $issuer, $nonce) {
		if($clientId !== $idTokenClaims['aud']) {
			throw new RuntimeException("The audience is invalid!");
		}

		if($issuer !== $idTokenClaims['iss']) {
			throw new RuntimeException("Invalid token issuer!");
		}

		if(!$this->sessionBasedHashService->validateSessionBasedHash($idTokenClaims['nonce']) || $nonce !== $idTokenClaims['nonce']) {
			throw new RuntimeException("The nonce is invalid!");
		}
	}
}