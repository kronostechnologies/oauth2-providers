<?php

namespace Kronos\OAuth2Providers\Google;

use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateAwareInterface;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use League\OAuth2\Client\Provider\Google;

class GoogleProvider extends Google implements StateAwareInterface
{
    use StateServiceAwareTrait;

    protected const DEFAULT_OPTIONS = [
        'accessType' => 'offline',
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
}
