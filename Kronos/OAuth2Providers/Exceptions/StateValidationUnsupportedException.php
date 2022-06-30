<?php

namespace Kronos\OAuth2Providers\Exceptions;

use RuntimeException;

class StateValidationUnsupportedException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct("Provider does not support validating the state.");
    }
}
