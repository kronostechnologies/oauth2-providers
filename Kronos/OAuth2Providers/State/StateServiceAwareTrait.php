<?php


namespace Kronos\OAuth2Providers\State;


trait StateServiceAwareTrait
{
    /**
     * @var StateServiceInterface
     */
    protected $stateService;

    protected function getRandomState($length = 32)
    {
        return $this->stateService->generateState();
    }

    /**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state){
	    return $this->stateService->validateState($state);
	}

    /**
     * @return StateServiceInterface
     */
    public function getStateService()
    {
        return $this->stateService;
    }

    /**
     * @param StateServiceInterface $stateService
     */
    public function setStateService(StateServiceInterface $stateService)
    {
        $this->stateService = $stateService;
    }
}