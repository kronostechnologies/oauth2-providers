<?php

namespace Kronos\OAuth2Providers\Outlook;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\Storage\AccessTokenStorageInterface;
use League\OAuth2\Client\Grant;
use League\OAuth2\Client\Token\AccessToken;
use Stevenmaguire\OAuth2\Client\Provider\Microsoft;

class OutlookOAuth2Service extends Microsoft implements OAuthServiceInterface, OAuthRefreshableInterface {

	const SCOPE_EMAIL =  "wl.emails";
	const SCOPE_BASIC_PROFILE = "wl.basic";
	const SCOPE_IMAP =  "wl.imap";
	const OFFLINE_ACCESS = 'wl.offline_access';

	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'id';

	protected $defaultAuthorizationUrlOptions = ['display'=>'popup'];

	/**
	 * @var AccessTokenStorageInterface
	 */
	private $accessTokenStore;

	/**
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 * @param AccessTokenStorageInterface $accessTokenStore
	 * @param array $collaborators
	 */
	public function __construct($clientId, $clientSecret, $redirectUri, AccessTokenStorageInterface $accessTokenStore,array $collaborators = []) {

		parent::__construct([
			'clientId'          => $clientId,
			'clientSecret'      => $clientSecret,
			'redirectUri'       => $redirectUri
		],$collaborators);

		$this->accessTokenStore = $accessTokenStore;
	}

	/**
	 * @return string[]
	 */
	protected function getDefaultScopes() {
		return [self::SCOPE_EMAIL,self::SCOPE_BASIC_PROFILE,self::SCOPE_IMAP,self::OFFLINE_ACCESS];
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
	 * @inheritdoc
	 */
	public function getAccessToken($grant, array $options = []){
		$token = parent::getAccessToken($grant, $options);
		$this->storeToken($token);
		return $token;
	}


	/**
	 * @param string $code
	 * @param array $options Additionnal options to pass getAccessToken()
	 * @return AccessToken
	 */
	public function getAccessTokenByAuthorizationCode($code, array $options = []) {
		return $this->getAccessToken('authorization_code', array_merge([
			'code' => $code
		], $options));
	}

	/**
	 * @param string $refresh_token
	 * @return AccessToken
	 */
	protected function getNewAccessTokenByRefreshToken($refresh_token){
        $options = [];
        $grant = new Grant\RefreshToken();
        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refresh_token
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);
        $token    = $this->createAccessToken($prepared, $grant);

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