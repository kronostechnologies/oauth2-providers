<?php

namespace Kronos\OAuth2Providers\Google;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\Storage\AccessTokenStorageInterface;
use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Token\AccessToken;

class GoogleOAuth2Service extends Google  implements OAuthServiceInterface {

	const USERINFO_EMAIL =  "https://www.googleapis.com/auth/userinfo.email";
	const USERINFO_PROFILE = "https://www.googleapis.com/auth/userinfo.profile";
	const MAIL_GOOGLE_COM =  "https://mail.google.com/";

	protected $defaultAuthorizationUrlOptions = ['approval_prompt'=>'force'];

	/**
	 * @var AccessTokenStorageInterface
	 */
	private $accessTokenStore;

	/**
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 * @param AccessTokenStorageInterface $accessTokenStore
	 */
	public function __construct($clientId, $clientSecret, $redirectUri, AccessTokenStorageInterface $accessTokenStore,array $collaborators = []) {

		parent::__construct([
			'clientId'          => $clientId,
			'clientSecret'      => $clientSecret,
			'redirectUri'       => $redirectUri,
			'accessType'        => 'offline',
		],$collaborators);

		$this->accessTokenStore = $accessTokenStore;
	}

	/**
	 * @return string[]
	 */
	protected function getDefaultScopes() {
		return [self::USERINFO_PROFILE,self::USERINFO_EMAIL,self::MAIL_GOOGLE_COM];
	}

	/**
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token)
	{
		return 'https://www.googleapis.com/oauth2/v2/userinfo?' . http_build_query([
			'alt'    => 'json',
		]);
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
	 * @param string $code
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code) {
		$token = $this->getAccessToken('authorization_code', [
			'code' => $code
		]);
		$this->storeToken($token);

		return $token;
	}

	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 * @throws InvalidRefreshTokenException
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
	 * @param AccessToken $token
	 */
	protected function storeToken(AccessToken $token){
			$this->accessTokenStore->storeAccessToken($token);
	}


	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 */
	protected function getNewAccessTokenByRefreshToken($refresh_token){
		$token = $this->getAccessToken('refresh_token', [
			'refresh_token' => $refresh_token
		]);

		$this->storeToken($token);

		return $token;
	}

	/**
	 * @param array $response
	 * @param AccessToken $token
	 * @return GoogleUser
	 */
	protected function createResourceOwner(array $response, AccessToken $token) {
		return new GoogleUser($response);
	}

	/**
	 * @return string
	 */
	protected function getSessionState(){
		$session_id = session_id();

		$generator = $this
			->getRandomFactory()
			->getMediumStrengthGenerator();

		$salt = $generator->generateString(8, RandomGenerator::CHAR_ALNUM);

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