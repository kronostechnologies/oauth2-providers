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

    public const VERSION_1_0 = parent::ENDPOINT_VERSION_1_0;
    public const VERSION_2_0 = parent::ENDPOINT_VERSION_2_0;

    protected const DEFAULT_SCOPES = [
        'openid',
        'profile',
        'email',
        'offline_access',
    ];

    public function __construct(array $options = [], array $collaborators = [])
    {
        if (isset($options['version'])) {
            $options['defaultEndPointVersion'] = $options['version'];
        }

        parent::__construct($options, $collaborators);

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    protected function createResourceOwner(array $response, AccessToken $token): MicrosoftUser
    {
        return new MicrosoftUser($response);
    }

    protected function getDefaultScopes(): array
    {
        return array_merge(parent::getDefaultScopes(), self::DEFAULT_SCOPES);
    }
}
