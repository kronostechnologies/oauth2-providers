<?php

namespace Kronos\OAuth2Providers\Microsoft;

use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateAwareInterface;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use League\OAuth2\Client\Token\AccessToken;
use TheNetworg\OAuth2\Client\Provider\Azure;

class MicrosoftProvider extends Azure implements StateAwareInterface
{
    use StateServiceAwareTrait;

    protected const DEFAULT_AUTH_OPTIONS = [
        'prompt' => 'consent',
    ];

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    public function getAuthorizationUrl(array $options = []): string
    {
        return parent::getAuthorizationUrl(
            array_merge(self::DEFAULT_AUTH_OPTIONS, $options)
        );
    }

    protected function createResourceOwner(array $response, AccessToken $token): MicrosoftUser
    {
        return new MicrosoftUser($response);
    }
}
