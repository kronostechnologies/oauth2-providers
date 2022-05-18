<?php

namespace Kronos\OAuth2Providers\Openid;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenInterface;
use Kronos\OAuth2Providers\OpenidServiceInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class OpenIdProvider extends AbstractProvider implements OpenidServiceInterface
{
    use BearerAuthorizationTrait;

    /**
     * @var OpenidProviderOptions
     */
    protected $options;

    /**
     * @var array
     */
    protected $openidConfiguration;

    /**
     * @var OpenidProviderCollaborators
     */
    protected $collaborators;

    private JwksResponseParser $jwksResponseParser;

    /**
     * Constructs an Openid Connect service provider.
     *
     * @param OpenidProviderOptions $options
     * @param OpenidProviderCollaborators $collaborators
     * @throws IdentityProviderException
     */
    public function __construct(OpenidProviderOptions $options, OpenidProviderCollaborators $collaborators)
    {
        $this->collaborators = $collaborators;
        $this->collaborators->getGrantFactory()->setGrant('jwt_bearer', new JwtBearer);
        $this->options = $options;
        $this->jwksResponseParser = new JwksResponseParser();

        $this->setHttpClient($collaborators->getHttpClient());
        $this->openidConfiguration = $this->fetchOpenidConfiguration();

        $abstractProviderOptions = [
            'clientId' => $options->getClientId(),
            'clientSecret' => $options->getClientSecret(),
            'redirectUri' => $options->getRedirectUri()
        ];
        $abstractProviderCollaborators = [
            'grantFactory' => $collaborators->getGrantFactory(),
            'requestFactory' => $collaborators->getRequestFactory(),
            'httpClient' => $collaborators->getHttpClient(),
        ];
        parent::__construct($abstractProviderOptions, $abstractProviderCollaborators);
    }

    public function getBaseAuthorizationUrl()
    {
        return $this->openidConfiguration['authorization_endpoint'];
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->openidConfiguration['token_endpoint'];
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->openidConfiguration['userinfo_endpoint'];
    }

    protected function getDefaultScopes()
    {
        return ['openid'];
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    protected function getAuthorizationParameters(array $options)
    {
        $options['state'] = $options['state'] ?? $this->collaborators->getStateService()->generateState();
        $options['nonce'] = $options['nonce'] ?? $this->collaborators->getNonceService()->generateNonce();
        return parent::getAuthorizationParameters($options);
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (isset($data['odata.error']) || isset($data['error'])) {
            if (isset($data['odata.error']['message']['value'])) {
                $message = $data['odata.error']['message']['value'];
            } elseif (isset($data['error']['message'])) {
                $message = $data['error']['message'];
            } else {
                $message = $response->getReasonPhrase();
            }

            $responseArray = [
                'headers' => $response->getHeaders(),
                'body' => (string)$response->getBody()
            ];

            throw new IdentityProviderException(
                $message,
                $response->getStatusCode(),
                $responseArray
            );
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new OpenIdUser($response);
    }

    /**
     * Requests an access token using an 'authorization_code' grant.
     * @param string $code
     * @param array $options
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
     * Requests and creates an id token.
     *
     * @param string $idTokenJWT id token received from authorization code exchange
     * @return IdTokenInterface
     * @throws IdentityProviderException
     */
    public function parseIdToken(string $idTokenJWT): IdTokenInterface
    {
        return $this->createIdToken($idTokenJWT);
    }

    /**
     * Creates an id token from a response.
     *
     * The provider that was used to fetch the response can be used to provide
     * additional context.
     *
     * @param string $idTokenJWT idToken jwt
     * @return IdTokenInterface
     * @throws IdentityProviderException
     */
    protected function createIdToken(string $idTokenJWT): IdTokenInterface
    {
        return $this->collaborators->getIdTokenFactory()->createIdToken($idTokenJWT, $this->getJwtVerificationKeys(),
            $this->options->getClientId(), $this->openidConfiguration['issuer']);
    }

    /**
     * @param string $state
     * @return bool
     */
    public function validateSate($state): bool
    {
        return $this->collaborators->getStateService()->validateState($state);
    }

    /**
     * @param string $nonce
     * @return bool
     */
    public function validateNonce($nonce): bool
    {
        return $this->collaborators->getNonceService()->validateNonce($nonce);
    }

    /**
     * Fetches the Openid Configuration from the openid configuration URL.
     *
     * @return array
     * @throws IdentityProviderException
     */
    protected function fetchOpenidConfiguration(): array
    {
        $request = $this->collaborators->getRequestFactory()->getRequestWithOptions('get',
            $this->options->getOpenidConfigurationUrl(), []);
        return $this->getParsedResponse($request);
    }

    /**
     * Get JWT verification keys.
     *
     * @return array
     * @throws IdentityProviderException
     */
    protected function getJwtVerificationKeys(): array
    {
        $request = $this->collaborators
            ->getRequestFactory()
            ->getRequestWithOptions('GET', $this->openidConfiguration['jwks_uri']);
        $response = $this->getParsedResponse($request);
        return $this->jwksResponseParser->getVerificationKeys($response);
    }

    /**
     * @return OpenidProviderOptions
     */
    public function getOptions(): OpenidProviderOptions
    {
        return $this->options;
    }

    /**
     * @return array
     */
    public function getOpenidConfiguration(): array
    {
        return $this->openidConfiguration;
    }

    /**
     * @return OpenidProviderCollaborators
     */
    public function getCollaborators(): OpenidProviderCollaborators
    {
        return $this->collaborators;
    }
}
