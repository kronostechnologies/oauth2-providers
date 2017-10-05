<?php

namespace Kronos\OAuth2Providers\Auth0;

use Kronos\OAuth2Providers\OAuthServiceInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Auth0 extends AbstractProvider implements OAuthServiceInterface {

	use BearerAuthorizationTrait;

	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'id';

	const DEFAULT_SCOPE_OPENID = 'openid';
	const DEFAULT_SCOPE_PROFILE = 'profile';
	const DEFAULT_SCOPES = [self::DEFAULT_SCOPE_OPENID, self::DEFAULT_SCOPE_PROFILE];

	protected $_base_authorization_url;
	protected $_base_access_token_url;
	protected $_resource_owner_details_url;

	/**
	 * Constructs an OAuth 2.0 service provider.
	 *
	 * @param array $options An array of options to set on this provider.
	 *     Required options are:
	 *     $options = [
	 *          'clientId' => '',
	 *          'clientSecret' => '',
	 *          'redirectUri' => '',
	 *          'state' => '',
	 *          'base_authorization_url' => '',
	 *          'base_access_token_url' => '',
	 *          'resource_owner_details_url' => ''
	 *          ];
	 *     Individual providers may introduce more options, as needed.
	 * @param array $collaborators An array of collaborators that may be used to
	 *     override this provider's default behavior. Collaborators include
	 *     `grantFactory`, `requestFactory`, and `httpClient`.
	 *     Individual providers may introduce more collaborators, as needed.
	 */
	public function __construct(array $options = [], array $collaborators = []) {

		parent::__construct($options, $collaborators);

		$this->_base_authorization_url = $options['base_authorization_url'];
		$this->_base_access_token_url = $options['base_access_token_url'];
		$this->_resource_owner_details_url = $options['resource_owner_details_url'];
	}

	/**
	 * Returns the base URL for authorizing a client.
	 *
	 * Eg. https://oauth.service.com/authorize
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl() {
		return $this->_base_authorization_url;
	}

	/**
	 * Returns the base URL for requesting an access token.
	 *
	 * Eg. https://oauth.service.com/token
	 *
	 * @param array $params
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params) {
		return $this->_base_access_token_url;
	}

	/**
	 * Returns the URL for requesting the resource owner's details.
	 *
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token) {
		return $this->_resource_owner_details_url;
	}

	/**
	 * Returns the default scopes used by this provider.
	 *
	 * This should only be the scopes that are required to request the details
	 * of the resource owner, rather than all the available scopes.
	 *
	 * @return array
	 */
	protected function getDefaultScopes() {
		return self::DEFAULT_SCOPES;
	}

	/**
	 * Requests an access token using an 'authorization_code' grant.
	 * @param string $authorization_code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code, array $options = []) {
		return $this->getAccessToken('authorization_code', array_merge([
			'code' => $code
		], $options));
	}

	/**
	 * Generates a resource owner object from a successful resource owner
	 * details request.
	 *
	 * @param  array $response
	 * @param  AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner(array $response, AccessToken $token) {
		return new Auth0User($response);
	}

	/**
	 * Checks a provider response for errors.
	 *
	 * @throws IdentityProviderException
	 * @param  ResponseInterface $response
	 * @param  array|string $data Parsed response data
	 * @return void
	 */
	protected function checkResponse(ResponseInterface $response, $data) {
		if(!empty($data['error'])) {
			$code = 0;
			$error = $data['error'];

			if(is_array($error)) {
				$code = $error['code'];
				$error = $error['message'];
			}

			throw new IdentityProviderException($error, $code, $data);
		}
	}

	/**
	 * Hack, returns sessionState, as per other providers.
	 *
	 * @param  int $length not used
	 * @return string
	 */
	protected function getRandomState($length = 32) {
		return $this->getSessionState();
	}

	/**
	 * @return string
	 */
	protected function getSessionState() {
		if(isset($this->state)) {
			return $this->state;
		}

		$session_id = session_id();
		$salt = bin2hex(random_bytes(4));
		$state = $salt . '_' . sha1($session_id . $salt);

		$this->state = $state;

		return $this->state;
	}

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state) {
		$session_id = session_id();
		list($salt, $hash) = explode('_', $state);

		if($hash == sha1($session_id . $salt)) {
			return true;
		}

		return false;
	}
}