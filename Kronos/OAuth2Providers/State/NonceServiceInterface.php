<?php

namespace Kronos\OAuth2Providers\State;

interface NonceServiceInterface
{
    /**
     * Generate nonce
     * @return string
     */
    public function generateNonce(): string;

    /**
     * Valide a nonce value returned in a id_token
     * @param string $nonce
     * @return bool
     */
    public function validateNonce($nonce): bool;
}
