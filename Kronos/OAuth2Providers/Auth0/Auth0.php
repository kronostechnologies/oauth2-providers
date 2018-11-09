<?php

namespace Kronos\OAuth2Providers\Auth0;

use Kronos\OAuth2Providers\OAuthServiceInterface;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Auth0 extends AbstractProvider implements OAuthServiceInterface {

	use BearerAuthorizationTrait;
	use StateServiceAwareTrait;

	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'id';

	const DEFAULT_SCOPE_OPENID = 'openid';
	const DEFAULT_SCOPE_PROFILE = 'profile';
	const DEFAULT_SCOPES = [self::DEFAULT_SCOPE_OPENID, self::DEFAULT_SCOPE_PROFILE];

	protected $baseAuthorizationUrl;
	protected $baseAccessTokenUrl;
	protected $resourceOwnerDetailsUrl;

    /**
     * @var StateServiceInterface
     */
    protected $stateService;

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

		$this->baseAuthorizationUrl = $options['baseAuthorizationUrl'] ?: $options['base_authorization_url'];
		$this->baseAccessTokenUrl = $options['baseAccessTokenUrl'] ?: $options['base_access_token_url'];
		$this->resourceOwnerDetailsUrl = $options['resourceOwnerDetailsUrl'] ?: $options['resource_owner_details_url'];

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
	}

	/**
	 * Returns the base URL for authorizing a client.
	 *
	 * Eg. https://oauth.service.com/authorize
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl() {
		return $this->baseAuthorizationUrl;
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
		return $this->baseAccessTokenUrl;
	}

	/**
	 * Returns the URL for requesting the resource owner's details.
	 *
	 * @param AccessToken $token
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token) {
		return $this->resourceOwnerDetailsUrl;
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
     * @param string $code
     * @param array $options
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
