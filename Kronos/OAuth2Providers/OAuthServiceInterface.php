<?php

namespace Kronos\OAuth2Providers;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

interface OAuthServiceInterface {
	/**
	 * @param AccessToken $access_token
	 * @return ResourceOwnerInterface
	 */
	public function getResourceOwner(AccessToken $access_token);

	/**
	 * @param string $code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code);

	/**
	 * @return string url for hand shake
	 */
	public function getAuthorizationUrl();

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state);
}