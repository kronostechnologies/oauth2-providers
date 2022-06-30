<?php

namespace Kronos\OAuth2Providers\Google;

use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateAwareInterface;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use League\OAuth2\Client\Provider\Google;

class GoogleProvider extends Google implements StateAwareInterface
{
    use StateServiceAwareTrait;

    protected const DEFAULT_SCOPES = [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://mail.google.com/',
    ];

    protected const DEFAULT_OPTIONS = [
        'accessType' => 'offline',
    ];

    protected const DEFAULT_AUTH_OPTIONS = [
        'prompt' => 'consent',
    ];

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct(
            array_merge(self::DEFAULT_OPTIONS, $options),
            $collaborators
        );

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    /**
     * @return string[]
     */
    protected function getDefaultScopes(): array
    {
        return self::DEFAULT_SCOPES;
    }

    public function getAuthorizationUrl(array $options = []): string
    {
        return parent::getAuthorizationUrl(
            array_merge(self::DEFAULT_AUTH_OPTIONS, $options)
        );
    }
}
