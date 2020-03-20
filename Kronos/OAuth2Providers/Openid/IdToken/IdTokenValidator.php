<?php

namespace Kronos\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\State\NonceServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use RuntimeException;

class IdTokenValidator
{

    /**
     * @var NonceServiceInterface
     */
    protected $nonceValidator;

    public function __construct(NonceServiceInterface $nonceValidator = null)
    {
        $this->nonceValidator = $nonceValidator ?? new SessionBasedHashService();
    }

    public function validateIdTokenClaims(array $idTokenClaims, $clientId, $issuer)
    {
        if ($clientId !== $idTokenClaims['aud']) {
            throw new RuntimeException('The audience is invalid!');
        }

        if ($issuer !== $idTokenClaims['iss']) {
            throw new RuntimeException('The issuer is invalid!');
        }

        if (!$this->nonceValidator->validateNonce($idTokenClaims['nonce'])) {
            throw new RuntimeException('The nonce is invalid!');
        }
    }
}
