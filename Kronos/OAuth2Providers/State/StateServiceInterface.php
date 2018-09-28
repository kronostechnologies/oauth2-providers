<?php


namespace Kronos\OAuth2Providers\State;


interface StateServiceInterface
{

    /**
     * Generate a state value for the authorization code flow.
     * @return string
     */
    public function generateState();

    /**
     * Valide a state value retured by the authorization code flow.
     * @param string $state
     * @return bool
     */
    public function validateState($state);

}