<?php

namespace Kronos\OAuth2Providers\Office365;

use Kronos\OAuth2Providers\MicrosoftGraph\MicrosoftGraphOAuth2Service;
use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;
use League\OAuth2\Client\Token\AccessToken;

class Office365OAuth2Service extends MicrosoftGraphOAuth2Service
{

    public const ACCESS_TOKEN_RESOURCE = 'https://outlook.office365.com';

    protected $apiUrlBase = 'https://outlook.office.com/api';
    protected $apiVersion = 'v2.0';
    protected $pathOAuth2 = '/oauth2'; // Need OAuth V1.0 for EWS


    /**
     * @inheritdoc
     * @psalm-suppress ParamNameMismatch
     */
    public function getAccessToken($grant = 'authorization_code', array $options = [])
    {
        if (!isset($options['resource'])) {
            $options['resource'] = self::ACCESS_TOKEN_RESOURCE;
        }

        return parent::getAccessToken($grant, $options);
    }

    /**
     * @inheritdoc
     * @psalm-suppress ImplementedReturnTypeMismatch Yeah, this design is broken
     * @return Office365User
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new Office365User($response);
    }

}
