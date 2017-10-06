<?php

namespace Kronos\OAuth2Providers\Office365;

use Kronos\OAuth2Providers\MicrosoftGraph\MicrosoftGraphOAuth2Service;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use League\OAuth2\Client\Token\AccessToken;

class Office365OAuth2Service extends MicrosoftGraphOAuth2Service implements OAuthServiceInterface, OAuthRefreshableInterface {

	protected $apiUrlBase = 'https://outlook.office.com/api';
	protected $apiVersion = 'v2.0';

	/**
	 * @inheritdoc
	 */
	protected function createResourceOwner(array $response, AccessToken $token)
	{
		return new Office365User($response);
	}

}