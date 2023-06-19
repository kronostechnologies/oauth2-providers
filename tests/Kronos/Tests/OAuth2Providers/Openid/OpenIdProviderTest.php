<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Psr7\Query;
use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\Uri;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\Openid\OpenIdOAuth2Service;
use Kronos\OAuth2Providers\Openid\OpenIdProvider;
use Kronos\OAuth2Providers\Openid\OpenidProviderCollaborators;
use Kronos\OAuth2Providers\Openid\OpenidProviderOptions;
use Kronos\OAuth2Providers\State\NonceServiceInterface;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\RequestFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

use const PHP_QUERY_RFC3986;

class OpenIdProviderTest extends TestCase
{
    private const VALID_OPTIONS = [
        'clientId' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'clientSecret' => 'qBqmkV1PIrDCbEdbMRU9lEoh',
        'redirectUri' => 'https://dev.kronos-dev.com/login/api/auth/ia/callback',
        'openidConfigurationUrl' => 'https://accounts.google.com/.well-known/openid-configuration'
    ];

    private const OPENID_CONFIG_ARRAY = [
        'issuer' => 'https://accounts.google.com',
        'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint' => 'https://www.googleapis.com/oauth2/v4/token',
        'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
    ];

    private const OPENID_CONFIG_RESPONSE_BODY = '{
	  "issuer": "https://accounts.google.com",
	  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
	  "token_endpoint": "https://www.googleapis.com/oauth2/v4/token",
	  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
	}';

    private const AN_ERROR_RESPONSE_BODY = '{
	  "error": {"message": "ERROR_MESSAGE_1234",
	            "code": 567890
	           }
	}';

    private const AN_ERROR_RESPONSE_ARRAY = [
        'error' => [
            'message' => 'ERROR_MESSAGE_1234',
            'code' => '567890'
        ]
    ];

    private const A_STATE_STRING = 'SOME_STATE_1234';
    private const A_NONCE_STRING = 'SOME_NONCE_1234';
    private const DEFAULT_OPENID_SCOPE = 'openid';
    private const DEFAULT_RESPONSE_TYPE = 'code';
    private const CUSTOM_SCOPE = 'profile';

    private const AN_AUTHORIZATION_CODE = 'some_code_1234';
    private const AN_AUTHORIZATION_CODE_ARRAY = ['code' => self::AN_AUTHORIZATION_CODE];

    /**
     * @var GrantFactory
     */
    protected $grantFactory;

    /**
     * @var RequestFactory
     */
    protected $requestFactory;

    /**
     * @var MockObject&HttpClient
     */
    protected $httpClient;

    /**
     * @var MockObject&StateServiceInterface
     */
    protected $stateService;

    /**
     * @var MockObject&NonceServiceInterface
     */
    protected $nonceService;

    /**
     * @var MockObject&IdTokenFactory
     */
    protected $idTokenFactory;

    /**
     * @var OpenidProviderOptions
     */
    protected $options;

    /**
     * @var OpenidProviderCollaborators
     */
    protected $collaborators;

    /**
     * @var OpenIdProvider
     */
    protected $provider;

    /**
     * @var OpenIdOAuth2Service
     */
    protected $service;

    /**
     * @var MockObject&BadResponseException
     */
    protected $badResponseException;

    public function setUp(): void
    {
        $this->grantFactory = new GrantFactory();
        $this->requestFactory = new RequestFactory();
        $this->httpClient = $this->createMock(HttpClient::class);
        $this->stateService = $this->createMock(StateServiceInterface::class);
        $this->nonceService = $this->createMock(NonceServiceInterface::class);
        $this->idTokenFactory = $this->createMock(IdTokenFactory::class);

        $this->options = new OpenidProviderOptions(self::VALID_OPTIONS);

        $this->collaborators = new OpenidProviderCollaborators(
            $this->grantFactory,
            $this->requestFactory,
            $this->httpClient,
            $this->stateService,
            $this->nonceService,
            $this->idTokenFactory
        );
    }

    private function buildAuthorizationUrl($state, $nonce, $scope = self::DEFAULT_OPENID_SCOPE)
    {
        $authorizationUrlValues = [
            'uri' => self::OPENID_CONFIG_ARRAY['authorization_endpoint'],
            'state' => $state,
            'nonce' => $nonce,
            'scope' => $scope,
            'response_type' => self::DEFAULT_RESPONSE_TYPE,
            'approval_prompt' => 'auto',
            'redirect_uri' => self::VALID_OPTIONS['redirectUri'],
            'client_id' => self::VALID_OPTIONS['clientId']
        ];

        $authorizationUrl = array_shift($authorizationUrlValues) . '?';
        $authorizationUrl .= http_build_query($authorizationUrlValues, '', '&', PHP_QUERY_RFC3986);

        return $authorizationUrl;
    }

    public function test_OptionsAndCollaborators_New_ShouldFetchOpenidConfig()
    {
        $openIdResponseBody = $this->givenOpenIdResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturn($openIdResponseBody);
        $this->provider = new OpenIdProvider($this->options, $this->collaborators);

        $actual = $this->provider->getOpenidConfiguration();

        $expected = self::OPENID_CONFIG_ARRAY;
        $this->assertEquals($expected, $actual);
    }

    public function test__getAuthorizationUrl_ShouldReturnDefaultAuthorizationUrlWithRandomNonceAndStateAndDefaultScope()
    {
        $openIdResponseBody = $this->givenOpenIdResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturn($openIdResponseBody);
        $this->stateService
            ->method('generateState')
            ->willReturn(self::A_STATE_STRING);
        $this->nonceService
            ->method('generateNonce')
            ->willReturn(self::A_NONCE_STRING);
        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $actual = $this->service->getAuthorizationUrl();

        $expected = $this->buildAuthorizationUrl(self::A_STATE_STRING, self::A_NONCE_STRING);
        $this->assertUriEquals($expected, $actual);
    }

    public function test_customScope_getAuthorizationUrl_ShouldReturnDefaultAuthorizationUrlWithRandomNonceAndStateAndCustomScope()
    {
        $openIdResponseBody = $this->givenOpenIdResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturn($openIdResponseBody);
        $this->stateService
            ->method('generateState')
            ->willReturn(self::A_STATE_STRING);
        $this->nonceService
            ->method('generateNonce')
            ->willReturn(self::A_NONCE_STRING);
        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $actual = $this->service->getAuthorizationUrl(['scope' => self::CUSTOM_SCOPE]);

        $expected = $this->buildAuthorizationUrl(self::A_STATE_STRING, self::A_NONCE_STRING, self::CUSTOM_SCOPE);
        self::assertUriEquals($expected, $actual);
    }

    public function test_InvalidCode_getIdToken_ShouldThrow()
    {
        $openIdResponse = $this->givenOpenIdResponseBody();
        $errorResponse = $this->givenErrorResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturnOnConsecutiveCalls($openIdResponse, $errorResponse);
        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

        $this->service->getAccessTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE);
    }

    public function test_InvalidCode_getIdTokenByAuthorizationCode_ShouldThrow()
    {
        $openIdResponse = $this->givenOpenIdResponseBody();
        $errorResponse = $this->givenErrorResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturnOnConsecutiveCalls($openIdResponse, $errorResponse);

        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $this->expectException(IdentityProviderException::class);
        $this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

        $this->service->getAccessTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE_ARRAY['code']);
    }

    public function test_ValidState_validateState_ShouldReturnTrue()
    {
        $openIdResponseBody = $this->givenOpenIdResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturn($openIdResponseBody);
        $this->stateService
            ->method('validateState')
            ->with(self::A_STATE_STRING)
            ->willReturn(true);

        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $this->assertTrue($this->service->validateState(self::A_STATE_STRING));
    }

    public function test_InvalidState_validateState_ShouldReturnFalse()
    {
        $openIdResponseBody = $this->givenOpenIdResponseBody();
        $this->httpClient
            ->method('send')
            ->willReturn($openIdResponseBody);
        $this->stateService
            ->method('validateState')
            ->with(self::A_STATE_STRING)
            ->willReturn(false);

        $this->provider = new OpenIdProvider($this->options, $this->collaborators);
        $this->service = new OpenIdOAuth2Service($this->provider);

        $this->assertFalse($this->service->validateState(self::A_STATE_STRING));
    }

    private static function assertUriEquals($expected, $actual)
    {
        $expectedUri = new Uri($expected);
        $actualUri = new Uri($actual);
        self::assertEquals($expectedUri->getHost(), $actualUri->getHost());
        self::assertEquals($expectedUri->getPath(), $actualUri->getPath());
        $expectedQuery = Query::parse($expectedUri->getQuery());
        $actualQuery = Query::parse($actualUri->getQuery());
        self::assertEquals($expectedQuery, $actualQuery);
    }

    private function givenErrorResponseBody(): ResponseInterface|MockObject
    {
        $errorStreamResponseBody = new Stream(fopen('data://text/plain,' . self::AN_ERROR_RESPONSE_BODY, 'rb'));
        $errorResponse = $this->createMock(ResponseInterface::class);
        $errorResponse
            ->method('getBody')
            ->willReturn($errorStreamResponseBody);
        $errorResponse
            ->method('getStatusCode')
            ->willReturn((int)self::AN_ERROR_RESPONSE_ARRAY['error']['code']);
        return $errorResponse;
    }

    private function givenOpenIdResponseBody(): ResponseInterface|MockObject
    {
        $openIdStreamResponseBody = new Stream(fopen('data://text/plain,' . self::OPENID_CONFIG_RESPONSE_BODY, 'rb'));
        $openIdResponse = $this->createMock(ResponseInterface::class);
        $openIdResponse
            ->method('getBody')
            ->willReturn($openIdStreamResponseBody);
        return $openIdResponse;
    }
}
