<?php

namespace Kronos\OAuth2Providers\State;

trait StateServiceAwareTrait
{
    /**
     * @return StateServiceInterface
     */
    abstract protected function getStateService(): StateServiceInterface;

    protected function getRandomState($length = 32): string
    {
        return $this->getStateService()->generateState();
    }

    /**
     * @param string $state
     * @return bool
     */
    public function validateSate($state): bool
    {
        return $this->getStateService()->validateState($state);
    }
}
