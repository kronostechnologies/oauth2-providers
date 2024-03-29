<?php

namespace Kronos\OAuth2Providers\State;

interface StateServiceInterface
{
    public function generateState(): string;

    public function validateState(string $state): bool;
}
