<?php

namespace Kronos\OAuth2Providers\Openid;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;

class JwksResponseParser
{
    /**
     * @param array{keys:array<array-key,array{kid:string,n:string,e:string,...}>} $response
     * @return array<string,Key>
     */
    public function getVerificationKeys(array $response): array
    {
        return JWK::parseKeySet($response, 'RS256');
    }
}
