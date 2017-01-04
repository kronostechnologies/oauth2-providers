<?php

namespace Kronos\OAuth2Providers\Storage;

use League\OAuth2\Client\Token\AccessToken;

interface AccessTokenStorageInterface {

	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 */
	public function retrieveAccessToken($refresh_token);

	/**
	 * @param $refresh_token
	 */
	public function storeAccessToken(AccessToken $accessToken);
}