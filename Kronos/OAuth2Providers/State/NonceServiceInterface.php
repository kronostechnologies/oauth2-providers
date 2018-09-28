<?php


namespace Kronos\OAuth2Providers\State;


interface NonceServiceInterface
{

    /**
     * Generate nonce
     * @return string
     */
    public function generateNonce();

    /**
     * Valide a nonce value retured in a id_token
     * @param string $nonce
     * @return bool
     */
    public function validateNonce($nonce);

}