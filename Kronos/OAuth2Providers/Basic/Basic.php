<?php

namespace Kronos\OAuth2Providers\Basic;

use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

abstract class Basic extends AbstractProvider implements OAuthServiceInterface
{

    use StateServiceAwareTrait;

    const STANDARD_AUTH_URL_PATH = 'oauth2/auth';
    const STANDARD_ACCESS_TOKEN_URL_PATH = 'oauth2/token';

    protected $authServerBaseUrl;

    /**
     * @var StateServiceInterface
     */
    protected $stateService;

    /**
     * Basic constructor.
     * @param string $clientId
     * @param string $clientSecret
     * @param string $redirectUri
     * @param string $authServerBaseUrl
     * @param array $collaborators
     */
    public function __construct($clientId, $clientSecret, $redirectUri, $authServerBaseUrl, array $collaborators = [])
    {

        parent::__construct([
            'clientId' => $clientId,
            'clientSecret' => $clientSecret,
            'redirectUri' => $redirectUri,
            'authServerBaseUrl' => $authServerBaseUrl,
        ], $collaborators);

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    /**
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->authServerBaseUrl . static::STANDARD_AUTH_URL_PATH;
    }

    /**
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->authServerBaseUrl . static::STANDARD_ACCESS_TOKEN_URL_PATH;
    }

    /**
     * @param string $code
     * @param array $options
     * @return AccessToken
     */
    public function getAccessTokenByAuthorizationCode($code, array $options = [])
    {
        return $this->getAccessToken('authorization_code', array_merge([
            'code' => $code
        ], $options));
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() != 200) {
            throw new IdentityProviderException($data['error'], $response->getStatusCode(), $data);
        }
    }

    /**
     * @return StateServiceInterface
     */
    public function getStateService()
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
