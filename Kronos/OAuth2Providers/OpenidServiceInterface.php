<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Openid\IdToken;

interface OpenidServiceInterface {

	/**
	 * @return string url for hand shake
	 */
	public function getAuthorizationUrl();

	/**
	 * @param string $code
	 * @return IdToken
	 */
	public function getIdTokenByAuthorizationCode($code);
}