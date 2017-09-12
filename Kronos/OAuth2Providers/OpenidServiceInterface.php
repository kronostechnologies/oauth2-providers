<?php

namespace Kronos\OAuth2Providers;

use Kronos\OAuth2Providers\Openid\IdToken;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

interface OpenidServiceInterface {
	/**
	 * @param IdToken $id_token
	 * @return ResourceOwnerInterface
	 */
	public function getResourceOwner(IdToken $id_token);

	/**
	 * @param string $code
	 * @return IdToken
	 */
	public function getIdTokenByAuthorizationCode($code);

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