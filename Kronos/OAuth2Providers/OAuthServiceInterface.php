<?php
namespace Kronos\OAuth2Providers;


use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
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
	 * @param string $refresh_token
	 * @throws InvalidRefreshTokenException
	 * @return AccessToken
	 */
	public function retrieveAccessToken($refresh_token);

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