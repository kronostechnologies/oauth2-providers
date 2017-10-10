<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenInterface;

interface OpenidServiceInterface {

	/**
	 * @return string url for hand shake
	 */
	public function getAuthorizationUrl();

	/**
	 * @param string $code
	 * @return IdTokenInterface
	 */
	public function getIdTokenByAuthorizationCode($code);
}