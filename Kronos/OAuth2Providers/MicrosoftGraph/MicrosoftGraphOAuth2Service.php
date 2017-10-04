<?php

namespace Kronos\OAuth2Providers\MicrosoftGraph;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\Storage\AccessTokenStorageInterface;
use League\OAuth2\Client\Token\AccessToken;

class MicrosoftGraphOAuth2Service extends \EightyOneSquare\OAuth2\Client\Provider\MicrosoftGraph implements OAuthServiceInterface, OAuthRefreshableInterface {

	/**
	 * @var AccessTokenStorageInterface
	 */
	private $accessTokenStore;

	/**
	 * @var string[]
	 */
	protected $defaultAuthorizationUrlOptions = ['prompt'=>'consent'];

	/**
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 * @param AccessTokenStorageInterface $accessTokenStore
	 * @param array $collaborators
	 */
	public function __construct($clientId, $clientSecret, $redirectUri, AccessTokenStorageInterface $accessTokenStore,array $collaborators = []) {

		$this->pathOAuth2 = '/oauth2/v2';

		parent::__construct([
			'clientId'          => $clientId,
			'clientSecret'      => $clientSecret,
			'redirectUri'       => $redirectUri,
			'accessType'        => 'offline',
		],$collaborators);

		$this->accessTokenStore = $accessTokenStore;
	}

	/**
	 * @param array $options
	 * @return string
	 */
	public function getAuthorizationUrl(array $options = []) {
		$options['state'] = $this->getSessionState();

		return parent::getAuthorizationUrl(
			array_merge($this->defaultAuthorizationUrlOptions,$options)
		);
	}

	/**
	 * @return string
	 */
	protected function getDefaultRessource(){
		return 'https://graph.microsoft.com';
	}

	/**
	 * @param string $code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code) {
		$token = $this->getAccessToken('authorization_code', [
			'code' => $code,
			'resource' => $this->getDefaultRessource(),
		]);

		$this->accessTokenStore->storeAccessToken($token);

		return $token;
	}

	/**
	 * @param string $refresh_token
	 * @throws InvalidRefreshTokenException
	 * @return AccessToken
	 */
	public function retrieveAccessToken($refresh_token) {
		if(empty($refresh_token)){
			throw new InvalidRefreshTokenException($refresh_token);
		}

		$token = $this->accessTokenStore->retrieveAccessToken($refresh_token);
		if($token) {
			return $token;
		}

		$token = $this->getNewAccessTokenByRefreshToken($refresh_token);

		return $token;
	}

	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 */
	protected function getNewAccessTokenByRefreshToken($refresh_token){
		$token = $this->getAccessToken('refresh_token', [
			'refresh_token' => $refresh_token]);

		$this->accessTokenStore->storeAccessToken($token);

		return $token;
	}

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state) {
		$session_id = session_id();
		list($salt, $hash) = explode('_', $state);
		if($hash == sha1($session_id . $salt)){
			return true;
		}
		return false;
	}

	/**
	 * @param array $response
	 * @param AccessToken $token
	 * @return MicrosoftGraphUser
	 */
	protected function createResourceOwner(array $response, AccessToken $token) {
		return new MicrosoftGraphUser($response);
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
}