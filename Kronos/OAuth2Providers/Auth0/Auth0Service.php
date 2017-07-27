<?php

namespace Kronos\OAuth2Providers\Auth0;

use Kronos\Common\Login\Exception;
use Kronos\Common\Route\Request;
use Kronos\Login\Application;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class Auth0Service {

	/**
	 * @var Auth0
	 */
	protected $_provider;

	public function __construct($client_name = '', Auth0 $provider = null) {
		$this->_provider = $provider ? $provider : $this->_createProvider($client_name);
	}

	protected function _createProvider($client_name = '', Application $application = null) {
		$app_instance = $application ? $application : Application::getInstance();
		$app_instance->setState($app_instance->getSessionStore()->getApplicationState());
		$client_options = $app_instance->getOption('auth0', 'clients', $client_name);

		if(!$client_options) {
			throw new Exception('Invalid Auth0 client name');
		}

		return new Auth0($client_options);
	}

	public function handleRequest(Request $request) {
		$get = $request->getGetData();

		// If we don't have an authorization code then get one
		if(!isset($get['code'])) {
			// Fetch the authorization URL from the provider; this returns the
			// urlAuthorize option and generates and applies any necessary parameters
			// (e.g. state).
			$authorizationUrl = $this->_provider->getAuthorizationUrl();

			// Get the state generated for you and store it to the session.
			$_SESSION['oauth2state'] = $this->_provider->getState();

			// Redirect the user to the authorization URL.
			header('Location: ' . $authorizationUrl);
			exit;
		}
		// Check given state against previously stored one to mitigate CSRF attack
		elseif(empty($get['state']) || (isset($_SESSION['oauth2state']) && $get['state'] !== $_SESSION['oauth2state'])) {
			if(isset($_SESSION['oauth2state'])) {
				unset($_SESSION['oauth2state']);
			}

			exit('Invalid Auth0 state');
		}
		else {
			try {
				// Try to get an access token using the authorization code grant.
				$accessToken = $this->_provider->getAccessTokenFromAuthorizationCode($get['code']);

				// Using the access token, we may look up details about the
				// resource owner.
				return $this->_provider->getResourceOwner($accessToken);
			}
			catch(IdentityProviderException $e) {
				// Failed to get the access token or user details.
				exit($e->getMessage());
			}
		}
	}
}