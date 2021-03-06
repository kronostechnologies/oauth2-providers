<?php

namespace Kronos\OAuth2Providers\Google;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Grant;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\Google;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;

class GoogleOAuth2Service extends Google implements OAuthServiceInterface, OAuthRefreshableInterface
{

    use StateServiceAwareTrait;

    public const USERINFO_EMAIL = 'https://www.googleapis.com/auth/userinfo.email';
    public const USERINFO_PROFILE = 'https://www.googleapis.com/auth/userinfo.profile';
    public const MAIL_GOOGLE_COM = 'https://mail.google.com/';

    protected $defaultAuthorizationUrlOptions = ['approval_prompt' => 'force'];

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
    public function __construct($clientId, $clientSecret, $redirectUri, array $collaborators = [])
    {

        parent::__construct([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
            'accessType' => 'offline',
        ], $collaborators);

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    /**
     * @return string[]
     */
    protected function getDefaultScopes()
    {
        return [self::USERINFO_PROFILE, self::USERINFO_EMAIL, self::MAIL_GOOGLE_COM];
    }

    /**
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return 'https://www.googleapis.com/oauth2/v2/userinfo?' . http_build_query([
                'alt' => 'json',
            ]);
    }

    /**
     * @param array $options
     * @return string
     */
    public function getAuthorizationUrl(array $options = [])
    {
        return parent::getAuthorizationUrl(
            array_merge($this->defaultAuthorizationUrlOptions, $options)
        );
    }

    /**
     * @param string $code
     * @param array $options Additionnal options to pass getAccessToken()
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    public function getAccessTokenByAuthorizationCode($code, array $options = []): AccessTokenInterface
    {
        return $this->getAccessToken('authorization_code', array_merge([
            'code' => $code
        ], $options));
    }

    /**
     * @param string $refresh_token
     * @return AccessTokenInterface
     * @throws IdentityProviderException
     */
    protected function getNewAccessTokenByRefreshToken($refresh_token): AccessTokenInterface
    {
        $options = [];
        $grant = new Grant\RefreshToken();
        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'refresh_token' => $refresh_token
        ];

        $params = $grant->prepareRequestParameters($params, $options);
        $request = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);
        $prepared = $this->prepareAccessTokenResponse($response);
        return $this->createAccessToken($prepared, $grant);
    }

    /**
     * @param string $refresh_token
     * @return AccessTokenInterface
     * @throws InvalidRefreshTokenException
     * @throws IdentityProviderException
     */
    public function retrieveAccessToken($refresh_token): AccessTokenInterface
    {
        if (empty($refresh_token)) {
            throw new InvalidRefreshTokenException($refresh_token);
        }

        return $this->getNewAccessTokenByRefreshToken($refresh_token);
    }

    /**
     * @param array $response
     * @param AccessToken $token
     * @return GoogleUser
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GoogleUser($response);
    }

    /**
     * @return StateServiceInterface
     */
    public function getStateService(): \Kronos\OAuth2Providers\State\StateServiceInterface
    {
        return $this->stateService;
    }

    /**
     * @param StateServiceInterface $stateService
     */
    public function setStateService(StateServiceInterface $stateService)
    {
        $this->stateService = $stateService;
    }
}
