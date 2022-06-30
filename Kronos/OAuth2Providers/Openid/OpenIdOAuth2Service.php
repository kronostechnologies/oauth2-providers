<?php

namespace Kronos\OAuth2Providers\Openid;

use Kronos\OAuth2Providers\OAuth2Service;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenInterface;
use Kronos\OAuth2Providers\OpenidServiceInterface;
use Kronos\OAuth2Providers\State\NonceServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceInterface;

/**
 * @template-extends OAuth2Service<OpenIdProvider, OpenIdUser>
 */
class OpenIdOAuth2Service extends OAuth2Service implements OpenidServiceInterface
{
    protected NonceServiceInterface $nonceService;
    protected StateServiceInterface $stateService;

    public function __construct(
        OpenIdProvider $provider,
        StateServiceInterface $stateService = null,
        NonceServiceInterface $nonceService = null
    ) {
        parent::__construct($provider);

        $this->stateService = $stateService ?? new SessionBasedHashService();
        $this->nonceService = $nonceService ?? new SessionBasedHashService();
    }

    public function parseIdToken(string $idTokenJWT): IdTokenInterface
    {
        return $this->provider->parseIdToken($idTokenJWT);
    }

    public function validateNonce(string $nonce): bool
    {
        return $this->nonceService->validateNonce($nonce);
    }
}
