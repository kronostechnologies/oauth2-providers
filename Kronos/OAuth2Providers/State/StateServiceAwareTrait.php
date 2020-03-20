<?php


namespace Kronos\OAuth2Providers\State;


trait StateServiceAwareTrait
{

    /**
     * @return StateServiceInterface
     */
    abstract protected function getStateService();

    protected function getRandomState($length = 32)
    {
        return $this->getStateService()->generateState();
    }

    /**
     * @param string $state
     * @return bool
     */
    public function validateSate($state)
    {
        return $this->getStateService()->validateState($state);
    }
}
