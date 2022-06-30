<?php

namespace Kronos\OAuth2Providers\Auth0;

use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateAwareInterface;
use Kronos\OAuth2Providers\State\StateServiceAwareTrait;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Auth0Provider extends AbstractProvider implements StateAwareInterface
{
    use BearerAuthorizationTrait;
    use StateServiceAwareTrait;

    protected const DEFAULT_SCOPES = [
        'openid',
        'profile',
    ];

    protected string $baseAuthorizationUrl;
    protected string $baseAccessTokenUrl;
    protected string $resourceOwnerDetailsUrl;

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        $this->baseAuthorizationUrl = $options['baseAuthorizationUrl'] ?? '';
        $this->baseAccessTokenUrl = $options['baseAccessTokenUrl'] ?? '';
        $this->resourceOwnerDetailsUrl = $options['resourceOwnerDetailsUrl'] ?? '';

        if (empty($collaborators['stateService'])) {
            $collaborators['stateService'] = new SessionBasedHashService();
        }
        $this->setStateService($collaborators['stateService']);
    }

    public function getBaseAuthorizationUrl(): string
    {
        return $this->baseAuthorizationUrl;
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->baseAccessTokenUrl;
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->resourceOwnerDetailsUrl;
    }

    protected function getDefaultScopes(): array
    {
        return self::DEFAULT_SCOPES;
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new Auth0User($response);
    }

    /**
     * @inheritdoc
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data['error'])) {
            $code = 0;
            $error = $data['error'];

            if (is_array($error)) {
                $code = $error['code'];
                $error = $error['message'];
            }

            throw new IdentityProviderException($error, $code, $data);
        }
    }
}
