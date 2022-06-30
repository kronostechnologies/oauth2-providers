<?php

namespace Kronos\OAuth2Providers\State;

trait StateServiceAwareTrait
{
    protected StateServiceInterface $stateService;

    public function getStateService(): StateServiceInterface
    {
        return $this->stateService;
    }

    public function setStateService(StateServiceInterface $stateService): void
    {
        $this->stateService = $stateService;
    }

    protected function getRandomState($length = 32): string
    {
        return $this->getStateService()->generateState();
    }

    public function validateState(string $state): bool
    {
        return $this->getStateService()->validateState($state);
    }
}
