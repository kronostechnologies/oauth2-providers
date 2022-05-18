<?php

namespace Kronos\OAuth2Providers\Openid;

use Firebase\JWT\JWT;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

class JwksResponseParser
{
    /**
     * @param array{keys:array<array-key,array{kid:string,n:string,e:string}>} $response
     * @return array<string,string>
     */
    public function getVerificationKeys(array $response): array
    {
        $keys = [];
        if (!empty($response['keys'])) {
            foreach ($response['keys'] as $keyinfo) {
                $keys[$keyinfo['kid']] = $this->decodeKey($keyinfo);
            }
        }

        return array_filter($keys);
    }

    /**
     * Decodes a JWT verification key.
     *
     * @param array{kid:string,n:string,e:string} $keyinfo
     * @return string|false
     */
    private function decodeKey(array $keyinfo)
    {
        $modulus = $keyinfo['n'];
        $exponent = $keyinfo['e'];
        $rsa = new RSA();

        $modulus = new BigInteger(JWT::urlsafeB64Decode($modulus), 256);
        $exponent = new BigInteger(JWT::urlsafeB64Decode($exponent), 256);

        /**
         * @psalm-suppress UndefinedDocblockClass broken annotation in library
         * @psalm-suppress InvalidArgument
         */
        $publicKey = $rsa->_convertPublicKey($modulus, $exponent);
        $rsa->loadKey($publicKey);
        $rsa->setPublicKey();

        return $rsa->getPublicKey();
    }
}
