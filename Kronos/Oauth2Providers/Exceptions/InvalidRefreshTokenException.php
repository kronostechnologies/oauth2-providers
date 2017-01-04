<?php

namespace Kronos\Oauth2Providers\Exceptions;

use Exception;

class InvalidRefreshTokenException extends Exception {
	public function __construct($refreshToken) {
		parent::__construct("Invalid refresh token.");
	}


}