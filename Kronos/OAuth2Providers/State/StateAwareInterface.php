<?php

namespace Kronos\OAuth2Providers\State;

interface StateAwareInterface
{
    public function validateState(string $state): bool;
}
