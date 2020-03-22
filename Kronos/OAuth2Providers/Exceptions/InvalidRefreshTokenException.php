<?php

namespace Kronos\OAuth2Providers\Exceptions;

use RuntimeException;

class InvalidRefreshTokenException extends RuntimeException
{
    public function __construct($refreshToken)
    {
        parent::__construct("Invalid refresh token. $refreshToken");
    }
}
