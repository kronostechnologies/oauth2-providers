<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use Firebase\JWT\JWT;
use RuntimeException;

class IdTokenParser {

	/**
	 * Returns the array of claims parsed from a raw JWT id token.
	 *
	 * @param string $idTokenString
	 * @param array $keys
	 * @return array
	 */
	public function parseIdToken($idTokenString, $keys) {
		$idTokenClaims = null;

		try {
			$tks = explode('.', $idTokenString);

			if(count($tks) == 3 && !empty($tks[2])) {
				$idTokenClaims = $this->decodeJWT($idTokenClaims, $keys);
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

	protected function decodeJWT($idTokenString, $keys){
		return (array)JWT::decode($idTokenString, $keys, ['RS256']);
	}
}