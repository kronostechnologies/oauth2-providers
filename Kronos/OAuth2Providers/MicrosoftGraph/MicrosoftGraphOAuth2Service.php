<?php

namespace Kronos\OAuth2Providers\MicrosoftGraph;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Grant;
use League\OAuth2\Client\Token\AccessToken;

class MicrosoftGraphOAuth2Service extends \EightyOneSquare\OAuth2\Client\Provider\MicrosoftGraph implements OAuthServiceInterface, OAuthRefreshableInterface {

    use StateServiceAwareTrait;

	/**
	 * @var string[]
	 */
	protected $defaultAuthorizationUrlOptions = ['prompt'=>'consent'];

    /**
     * @var StateServiceInterface
     */
    protected $stateService;

	/**
	 * @param string $clientId
	 * @param string $clientSecret
	 * @param string $redirectUri
	 * @param array $collaborators
	 */
	public function __construct($clientId, $clientSecret, $redirectUri, array $collaborators = []) {
		parent::__construct([
			'clientId'          => $clientId,
			'clientSecret'      => $clientSecret,
			'redirectUri'       => $redirectUri,
			'accessType'        => 'offline',
		],$collaborators);

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
	}

	/**
	 * @param array $options
	 * @return string
	 */
	public function getAuthorizationUrl(array $options = []) {
		return parent::getAuthorizationUrl(
			array_merge($this->defaultAuthorizationUrlOptions,$options)
		);
	}

    /**
     * @param string $code
     * @param array $options
     * @return AccessToken
     */
	public function getAccessTokenByAuthorizationCode($code, array $options = []) {
		return $this->getAccessToken('authorization_code', array_merge([
			'code' => $code,
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

		return $this->getNewAccessTokenByRefreshToken($refresh_token);
	}

	/**
	 * @param array $response
	 * @param AccessToken $token
	 * @return MicrosoftGraphUser
	 */
	protected function createResourceOwner(array $response, AccessToken $token) {
		return new MicrosoftGraphUser($response);
	}
}