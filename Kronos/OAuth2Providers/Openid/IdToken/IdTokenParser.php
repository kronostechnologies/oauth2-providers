<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use RuntimeException;

class IdTokenParser
{
    /**
     * Returns the array of claims parsed from a raw JWT id token.
     *
     * @param string $idTokenString
     * @param array<string, Key> $keys
     * @return array
     */
    public function parseIdToken(string $idTokenString, array $keys): array
    {
        try {
            $tks = explode('.', $idTokenString);

            if (count($tks) == 3 && !empty($tks[2])) {
                $idTokenClaims = $this->decodeJWT($idTokenString, $keys);
            } else {
                throw new RuntimeException('Unsigned id_token');
            }
        } catch (RuntimeException $e) {
            throw new RuntimeException('Unable to parse the id_token!', 0, $e);
        }

        return $idTokenClaims;
    }

    protected function decodeJWT($idTokenString, $keys)
    {
        return (array)JWT::decode($idTokenString, $keys);
    }
}
