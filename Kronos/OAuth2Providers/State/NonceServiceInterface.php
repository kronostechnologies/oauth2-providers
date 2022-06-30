<?php

namespace Kronos\OAuth2Providers\State;

interface NonceServiceInterface
{
    public function generateNonce(): string;

    public function validateNonce(string $nonce): bool;
}
