<?php
namespace Kronos\Oauth2Providers;


use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;

interface OAuthServiceInterface {
	/**
	 * @param AccessToken $access_token
	 * @return ResourceOwnerInterface
	 */
	function getResourceOwner(AccessToken $access_token);

	/**
	 * @param string $code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationcode($code);

	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 */
	public function retrieveAccessToken($refresh_token);

	/**
	 * @return string url for hand shake
	 */
	public function getAuthorizationUrl();
}