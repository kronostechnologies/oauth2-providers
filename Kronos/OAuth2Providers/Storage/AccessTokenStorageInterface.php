<?php

namespace Kronos\OAuth2Providers\Storage;

/**
 * @copyright Copyright (c) Maxime Demers <mdemers@kronostechnologies.com>
 * @license http://opensource.org/licenses/MIT MIT
 * @link https://packagist.org/packages/kronos/oauth2-providers Packagist
 * @link https://github.com/kronostechnologies/oauth2-providers GitHub
 * Date: 2016-12-22
 * Time: 9:34 AM
 */

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