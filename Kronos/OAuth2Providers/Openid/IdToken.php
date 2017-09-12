<?php

namespace Kronos\OAuth2Providers\Openid;

use Firebase\JWT\JWT;
use InvalidArgumentException;
use JsonSerializable;
use RuntimeException;

class IdToken implements JsonSerializable {

	/**
	 * @var string
	 */
	protected $idToken;

	/**
	 * @var string
	 */
	protected $idTokenIdKey;

	/**
	 * @var array
	 */
	protected $idTokenClaims;

	/**
	 * Constructs an id token.
	 *
	 * @param array $options An array of options returned by the service provider
	 *     in the id token request. The `id_token` option is required.
	 * @param GenericOpenIdProvider $provider
	 */
	public function __construct(array $options = [], GenericOpenIdProvider $provider) {
		if(empty($options['id_token'])) {
			throw new InvalidArgumentException('Required option not passed: "id_token"');
		}

		$this->idToken = $options['id_token'];
		$this->idTokenIdKey = $provider::ID_TOKEN_RESOURCE_OWNER_ID;

		$keys = $provider->getJwtVerificationKeys();

		$this->idTokenClaims = $this->parseIdToken($this->idToken, $keys);

		$this->validateIdToken($provider);
	}

	/**
	 * Returns this token's claims.
	 *
	 * @return array
	 */
	public function getClaims() {
		return $this->idTokenClaims;
	}

	/**
	 * Returns this token's 'user id', corresponding to the claim identified at initialization time by the provider.
	 *
	 * @return mixed
	 */
	public function getUserId() {
		return $this->idTokenClaims[$this->idTokenIdKey];
	}

	/**
	 * Returns this token's raw JWT string.
	 *
	 * @return string
	 */
	public function getIdToken() {
		return $this->idToken;
	}

	/**
	 * Returns the array of claims parsed from a raw JWT id token.
	 *
	 * @param $id_token
	 * @param $keys
	 * @return array
	 */
	public function parseIdToken($id_token, $keys) {
		$idTokenClaims = null;

		try {
			$tks = explode('.', $id_token);
			// Check if the id_token contains signature
			if(count($tks) == 3 && !empty($tks[2])) {
				$idTokenClaims = (array)JWT::decode($this->idToken, $keys, ['RS256']);
			}
			else {
				throw new RuntimeException("Unsigned id_token");
			}
		}
		catch(RuntimeException $e) {
			throw new RuntimeException("Unable to parse the id_token!");
		}

		return $idTokenClaims;
	}

	/**
	 * Validates this token using a provider.
	 *
	 * @param GenericOpenIdProvider $provider
	 */
	protected function validateIdToken(GenericOpenIdProvider $provider) {

		if(!$provider->validateNonce($this->idTokenClaims['nonce'])) {
			throw new RuntimeException("The nonce is invalid!");
		}
		if($provider->getClientId() != $this->idTokenClaims['aud']) {
			throw new RuntimeException("The audience is invalid!");
		}
		if($this->idTokenClaims['nbf'] > time() || $this->idTokenClaims['exp'] < time()) {
			// Additional validation is being performed in firebase/JWT itself
			throw new RuntimeException("The id_token is invalid!");
		}
		$tenant = $provider->getOpenidConfiguration();
		if($this->idTokenClaims['iss'] != $tenant['issuer']) {
			throw new RuntimeException("Invalid token issuer!");
		}
	}

	/**
	 * Specify data which should be serialized to JSON
	 * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
	 * @return mixed data which can be serialized by <b>json_encode</b>,
	 * which is a value of any type other than a resource.
	 * @since 5.4.0
	 */
	function jsonSerialize() {
		return $this->idTokenClaims;
	}
}