<?php

namespace Kronos\OAuth2Providers\Auth0;

use Kronos\Common\Debug;
use Kronos\Common\Login\Exception;
use Kronos\Common\Route\Request;
use Kronos\Login\Application;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class Auth0Service {

	/**
	 * @var Auth0
	 */
	private $_provider;

	public function __construct($client_name) {
		$this->_provider = $this->_createProvider($client_name);
	}

	private function _createProvider($client_name) {
		Application::getInstance()->setState(Application::getInstance()->getSessionStore()->getApplicationState());
		$client_options = Application::getInstance()->getOption('auth0', 'clients', $client_name);

		Debug::Debug('$client_options');
		Debug::Debug($client_options);

		if(!$client_options) {
			throw new Exception('Invalid Auth0 client name');
		}

		return new Auth0($client_options);
	}

	public function authorize(Request $request){
		$get = $request->getGetData();

		// If we don't have an authorization code then get one
		if(!isset($get['code'])) {
			Debug::Debug('no code, -> redirect');

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
		elseif(empty($get['state']) || (isset($_SESSION['oauth2state']) && $get['state'] !== $_SESSION['oauth2state'])){
			Debug::Debug('code, -> invalid state');
			if(isset($_SESSION['oauth2state'])) {
				unset($_SESSION['oauth2state']);
			}

			exit('Invalid state');
		}else{
			Debug::Debug('code, -> getting token');
			try {
				// Try to get an access token using the authorization code grant.
				$accessToken = $this->_provider->getAccessToken('authorization_code', [
					'code' => $get['code']
				]);

				// We have an access token, which we may use in authenticated
				// requests against the service provider's API.
				Debug::Debug('Access Token: ' . $accessToken->getToken());

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