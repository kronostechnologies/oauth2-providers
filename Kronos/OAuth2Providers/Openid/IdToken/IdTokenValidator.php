<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\SessionBasedHashService;
use RuntimeException;

class IdTokenValidator {

	/**
	 * @var SessionBasedHashService
	 */
	protected $hashService;

	public function __construct(SessionBasedHashService $sessionBasedHashService = null) {
		$this->hashService = empty($sessionBasedHashService) ? new SessionBasedHashService() : $sessionBasedHashService;
	}

	public function validateIdTokenClaims(array $idTokenClaims, $clientId, $issuer) {
		if($clientId !== $idTokenClaims['aud']) {
			throw new RuntimeException('The audience is invalid!');
		}

		if($issuer !== $idTokenClaims['iss']) {
			throw new RuntimeException('The issuer is invalid!');
		}

		if(!$this->hashService->validateSessionBasedHash($idTokenClaims['nonce'])) {
			throw new RuntimeException('The nonce is invalid!');
		}
	}
}