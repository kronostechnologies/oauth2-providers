<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use League\OAuth2\Client\Token\AccessToken;

interface OAuthRefreshableInterface {

	/**
	 * @param string $refresh_token
	 * @throws InvalidRefreshTokenException
	 * @return AccessToken
	 */
	public function retrieveAccessToken($refresh_token);
}