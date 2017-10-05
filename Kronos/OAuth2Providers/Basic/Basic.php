<?php
namespace Kronos\OAuth2Providers\Basic;

use Kronos\OAuth2Providers\OAuthServiceInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

abstract class Basic extends AbstractProvider implements OAuthServiceInterface {

	const STANDARD_AUTH_URL_PATH = 'oauth2/auth';
	const STANDARD_ACCESS_TOKEN_URL_PATH = 'oauth2/token';

	protected $authServerBaseUrl;

	/**
	 * Basic constructor.
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 * @param string $authServerBaseUrl
	 * @param array $collaborators
	 */
	public function __construct($clientId, $clientSecret, $redirectUri,$authServerBaseUrl, array $collaborators = []) {

		parent::__construct([
			'clientId'          => $clientId,
			'clientSecret'      => $clientSecret,
			'redirectUri'       => $redirectUri,
			'authServerBaseUrl' => $authServerBaseUrl,
		], $collaborators);
	}

	/**
	 * @param array $options
	 * @return string
	 */
	public function getAuthorizationUrl(array $options = []) {
		$options['state'] = $this->getSessionState();

		return parent::getAuthorizationUrl($options);
	}

	/**
	 * @return string
	 */
	public function getBaseAuthorizationUrl() {
		return $this->authServerBaseUrl.static::STANDARD_AUTH_URL_PATH;
	}

	/**
	 * @param array $params
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params) {
		return $this->authServerBaseUrl.static::STANDARD_ACCESS_TOKEN_URL_PATH;
	}

	/**
	 * @param string $code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code, array $options = []) {
		return $this->getAccessToken('authorization_code', array_merge([
			'code' => $code
		], $options));
	}

	protected function checkResponse(ResponseInterface $response, $data) {
		if($response->getStatusCode()!= 200){
			throw new IdentityProviderException($data['error'], $response->getStatusCode(), $data);
		}
	}

	/**
	 * @return string
	 */
	protected function getSessionState(){
		$session_id = session_id();
		$salt = bin2hex(random_bytes(4));
		$state = $salt . '_'. sha1($session_id . $salt);

		return $state;
	}

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state){
		$session_id = session_id();
		list($salt, $hash) = explode('_', $state);
		if($hash == sha1($session_id . $salt)){
			return true;
		}
		return false;

	}

}