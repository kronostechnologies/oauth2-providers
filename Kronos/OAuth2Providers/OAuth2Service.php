<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\StateValidationUnsupportedException;
use Kronos\OAuth2Providers\State\StateAwareInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

/**
 * @template P of AbstractProvider
 * @template R of ResourceOwnerInterface
 * @template-implements OAuthServiceInterface<R>
 */
class OAuth2Service implements OAuthServiceInterface
{
    use RequestsAccessToken;

    /** @var P */
    protected AbstractProvider $provider;

    /**
     * @param P $provider
     */
    public function __construct(AbstractProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * @return R
     */
    public function getResourceOwner(AccessToken $accessToken): ResourceOwnerInterface
    {
        /** @var R */
        return $this->provider->getResourceOwner($accessToken);
    }

    public function getAuthorizationUrl(array $options = []): string
    {
        return $this->provider->getAuthorizationUrl($options);
    }

    public function getState(): string
    {
        $state = $this->provider->getState();

        if (empty($state)) {
            throw new \RuntimeException("Tried to access state before it was generated.");
        }

        return $state;
    }

    public function validateState(string $state): bool
    {
        if ($this->provider instanceof StateAwareInterface) {
            return $this->provider->validateState($state);
        }

        throw new StateValidationUnsupportedException();
    }
}
