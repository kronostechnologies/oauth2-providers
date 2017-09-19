<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use BadMethodCallException;
use GuzzleHttp\Psr7\Request;
use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken;
use League\OAuth2\Client\Grant\Exception\InvalidGrantException;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\RequestFactory;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;
use GuzzleHttp\Client as HttpClient;
use Psr\Http\Message\ResponseInterface;

class GenericOpenidProviderTest extends PHPUnit_Framework_TestCase {

	const VALID_OPTIONS = [
		'clientId' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
		'clientSecret' => 'qBqmkV1PIrDCbEdbMRU9lEoh',
		'redirectUri' => 'https://dev.kronos-dev.com/login/api/auth/ia/callback',
		'openidConfigurationUrl' => 'https://accounts.google.com/.well-known/openid-configuration'
	];

	const OPENID_CONFIG_RESPONSE_BODY = '{
	 "issuer": "https://accounts.google.com",
	 "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
	 "token_endpoint": "https://www.googleapis.com/oauth2/v4/token",
	 "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
	}';

	const OPENID_CONFIG_ARRAY = [
		'issuer' => 'https://accounts.google.com',
		'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
		'token_endpoint' => 'https://www.googleapis.com/oauth2/v4/token',
		'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
	];

	const ID_TOKEN_RESPONSE_BODY = '{
  "sub": "90342.ASDFJWFA",
  "aud": "164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com",
  "resource_owner_id": "90342.ASDFJWFA"
}';

	const ID_TOKEN_RESPONSE_ARRAY = [
		'sub' => '90342.ASDFJWFA',
		'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
		'resource_owner_id' => '90342.ASDFJWFA'
	];

	const AN_ERROR_RESPONSE_BODY = '{
  "error": {"message": "ERROR_MESSAGE_1234",
               "code": 567890
           }
}';

	const AN_ERROR_RESPONSE_ARRAY = [
		'error' => [
			'message' => 'ERROR_MESSAGE_1234',
			'code' => '567890'
		]
	];

	const A_REQUEST_OPTIONS_ARRAY = [
		'headers' => ['SOME_HEADERS'],
		'body' => 'SOME_REQUEST_BODY',
		'version' => '65.42'
	];

	const A_STATE_STRING = 'SOME_STATE_1234';
	const A_NONCE_STRING = 'SOME_NONCE_1234';
	const DEFAULT_OPENID_SCOPE = 'openid';
	const DEFAULT_RESPONSE_TYPE = 'code';
	const DEFAULT_APPROVAL_PROMPT = 'auto';
	const A_SCOPE_STRING = 'SOME_SCOPE';
	const A_RESOURCE_OWNER_ID = '90342.ASDFJWFA';
	const AN_AUTHORIZATION_GRANT = 'authorization_code';
	const AN_AUTHORIZATION_CODE = 'some_code_1234';
	const AN_AUTHORIZATION_CODE_ARRAY = ['code' => self::AN_AUTHORIZATION_CODE];
	const AN_INVALID_GRANT_STRING = 'InvalidGrant';
	const A_REQUEST_METHOD = 'GET';
	const A_URI = 'https://example.com';


	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|GrantFactory
	 */
	protected $grantFactory;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|RequestFactory
	 */
	protected $requestFactory;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|HttpClient
	 */
	protected $httpClient;

	/**
	 * @var array
	 */
	protected $collaborators;

	/**
	 * @var TestableGenericOpenidProvider
	 */
	protected $provider;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|ResponseInterface
	 */
	protected $response;

	/**
	 * @var array
	 */
	protected $options;

	//protected $config;

	public function setUp() {
		$this->grantFactory = $this->getMockBuilder(GrantFactory::class)
			//->setMethods(['setGrant', 'getGrant', 'checkGrant'])
			->setMethods(null)
			->getMock();

		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			//->setMethods(['getRequestWithOptions'])
			->setMethods(null)
			->getMock();

		$this->httpClient = $this->getMockBuilder(HttpClient::class)
			->setMethods(['send'])
			->getMock();

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];

		$this->response = $this->getMockForAbstractClass(ResponseInterface::class);

		$this->options = self::VALID_OPTIONS;
		$this->options['openidConfiguration'] = json_decode(self::OPENID_CONFIG_RESPONSE_BODY, true);
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);
	}

	private function setClientResponse($body = null) {
		if($body){
			$this->response->expects($this->once())
				->method('getBody')
				->willReturn($body);
		}
		$this->httpClient->expects($this->once())
			->method('send')
			->willReturn($this->response);
	}

	private function setClientToNeverExpectSendMethod() {
		$this->httpClient->expects($this->never())
			->method('send');
	}

	private function buildAuthorizationUrl($state, $nonce, $scope = self::DEFAULT_OPENID_SCOPE) {
		$authorizationUrlValues = [
			'uri' => self::OPENID_CONFIG_ARRAY['authorization_endpoint'],
			'state' => $state,
			'nonce' => $nonce,
			'scope' => $scope,
			'response_type' => self::DEFAULT_RESPONSE_TYPE,
			'approval_prompt' => self::DEFAULT_APPROVAL_PROMPT,
			'redirect_uri' => urlencode(self::VALID_OPTIONS['redirectUri']),
			'client_id' => self::VALID_OPTIONS['clientId']
		];

		$authorizationUrl = array_shift($authorizationUrlValues) . '?';
		foreach($authorizationUrlValues as $key => $value) {
			$authorizationUrl .= $key . '=' . $value . '&';
		}

		return rtrim($authorizationUrl, '&');
	}


	public function test_EmptyArgs_New_ShouldCreateNewCollaborators() {
		$this->setClientToNeverExpectSendMethod();

		$this->provider = new TestableGenericOpenidProvider();

		$this->assertNull($this->provider->getClientId());
		$this->assertNull($this->provider->getClientSecret());
		$this->assertNull($this->provider->getRedirectUri());
		$this->assertNull($this->provider->getOpenidConfigurationUrl());

		$this->assertInstanceOf(GrantFactory::class, $this->provider->getGrantFactory());
		$this->assertInstanceOf(RequestFactory::class, $this->provider->getRequestFactory());
		$this->assertInstanceOf(HttpClient::class, $this->provider->getHttpClient());
	}

	public function test_OptionsAndCollaborators_New_ShouldSetOptionsAndCollaboratorsAndFetchOpenidConfig() {
		$this->setClientResponse(self::OPENID_CONFIG_RESPONSE_BODY);

		unset($this->options['openidConfiguration']);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->assertEquals($this->options['clientId'], $this->provider->getClientId());
		$this->assertEquals($this->options['clientSecret'], $this->provider->getClientSecret());
		$this->assertEquals($this->options['redirectUri'], $this->provider->getRedirectUri());
		$this->assertEquals($this->options['openidConfigurationUrl'], $this->provider->getOpenidConfigurationUrl());
		$this->assertEquals(self::OPENID_CONFIG_ARRAY, $this->provider->getOpenidConfiguration());
	}

	public function test_OptionalOptions_New_ShouldSetOptionsAndConfig() {
		$this->setClientToNeverExpectSendMethod();

		$options = [
			'openidConfiguration' => self::OPENID_CONFIG_ARRAY,
			'state' => self::A_STATE_STRING,
			'nonce' => self::A_NONCE_STRING
		];
		$this->provider = new TestableGenericOpenidProvider($options, $this->collaborators);

		$this->assertEquals($options['openidConfiguration'], $this->provider->getOpenidConfiguration());
		$this->assertEquals($options['state'], $this->provider->getState());
		$this->assertEquals($options['nonce'], $this->provider->getNonce());
	}

	public function test_ValidOptionsWithConfig_getClientId_ShouldReturnClientId() {
		$expected = self::VALID_OPTIONS['clientId'];
		$actual = $this->provider->getClientId();

		$this->assertEquals($expected, $actual);
	}

	public function test_ValidOptions_getBaseAuthorizationUrl_ShouldReturnAuthorizeEndpoint() {
		$expected = self::OPENID_CONFIG_ARRAY['authorization_endpoint'];
		$actual = $this->provider->getBaseAuthorizationUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_ValidOptions_getBaseIdTokenUrl_ShouldReturnTokenEndpoint() {
		$expected = self::OPENID_CONFIG_ARRAY['token_endpoint'];
		$actual = $this->provider->getBaseIdTokenUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_EmptyOptions_getAuthorizationUrl_ShouldReturnDefaultAuthorizationUrlWithRandomNonceAndStateAndDefaultScope() {
		//Needs to be called first to set random state and nonce
		$actual = $this->provider->getAuthorizationUrl();
		$expected = $this->buildAuthorizationUrl($this->provider->getState(), $this->provider->getNonce());

		$this->assertEquals($expected, $actual);
	}

	public function test_EmptyOptions_getAuthorizationUrl_ShouldReturnAuthorizationUrlWithOptionsNonceStateAndScope() {
		$getAuthorizationUrlOptions = [
			'state' => self::A_STATE_STRING,
			'nonce' => self::A_NONCE_STRING,
			'scope' => self::A_SCOPE_STRING
		];

		$expected = $this->buildAuthorizationUrl(self::A_STATE_STRING, self::A_NONCE_STRING, self::A_SCOPE_STRING);
		$actual = $this->provider->getAuthorizationUrl($getAuthorizationUrlOptions);

		$this->assertEquals($expected, $actual);
	}

	public function test_GrantAndCode_getIdToken_ShouldFetchAndCreateIdToken() {
		$this->setClientResponse(self::ID_TOKEN_RESPONSE_BODY);

		$idToken = $this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);

		$expected = self::ID_TOKEN_RESPONSE_ARRAY;
		$actual = null;
		if($idToken instanceof IdTokenStub) {
			$actual = $idToken->options;
		}

		$this->assertEquals($expected, $actual);
	}

	public function test_GrantNoCode_getIdToken_ShouldThrow() {
		$this->setClientToNeverExpectSendMethod();

		$this->expectException(BadMethodCallException::class);
		$this->expectExceptionMessage('Required parameter not passed: "code"');

		$this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT);
	}

	public function test_InvalidGrant_getIdToken_ShouldThrow() {
		$this->setClientToNeverExpectSendMethod();

		$this->expectException(InvalidGrantException::class);
		$this->expectExceptionMessage('Grant "League\OAuth2\Client\Grant\\' . self::AN_INVALID_GRANT_STRING . '" must extend AbstractGrant');

		$this->provider->getIdToken(self::AN_INVALID_GRANT_STRING);
	}

	public function test_InvalidCode_getIdToken_ShouldThrow() {
		$this->setClientResponse(self::AN_ERROR_RESPONSE_BODY);
		$this->response->expects($this->once())
			->method('getStatusCode')
			->willReturn(self::AN_ERROR_RESPONSE_ARRAY['error']['code']);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

		$this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);
	}

	public function test_GrantAndCode_getIdTokenPreparedResponse_ShouldFetchAndPrepareIdTokenResponse() {
		$this->setClientResponse(self::ID_TOKEN_RESPONSE_BODY);

		$expected = self::ID_TOKEN_RESPONSE_ARRAY;
		$actual = $this->provider->getIdTokenPreparedResponse(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);

		$this->assertEquals($expected, $actual);
	}

	public function test_GrantNoCode_getIdTokenPreparedResponse_ShouldThrow() {
		$this->setClientToNeverExpectSendMethod();

		$this->expectException(BadMethodCallException::class);
		$this->expectExceptionMessage('Required parameter not passed: "code"');

		$this->provider->getIdTokenPreparedResponse(self::AN_AUTHORIZATION_GRANT);
	}

	public function test_InvalidGrant_getIdTokenPreparedResponse_ShouldThrow() {
		$this->setClientToNeverExpectSendMethod();

		$this->expectException(InvalidGrantException::class);
		$this->expectExceptionMessage('Grant "League\OAuth2\Client\Grant\\' . self::AN_INVALID_GRANT_STRING . '" must extend AbstractGrant');

		$this->provider->getIdTokenPreparedResponse(self::AN_INVALID_GRANT_STRING);
	}

	public function test_InvalidCode_getIdTokenPreparedResponse_ShouldThrow() {
		$this->setClientResponse(self::AN_ERROR_RESPONSE_BODY);
		$this->response->expects($this->once())
			->method('getStatusCode')
			->willReturn(self::AN_ERROR_RESPONSE_ARRAY['error']['code']);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

		$this->provider->getIdTokenPreparedResponse(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);
	}

	public function test_WithCode_getIdTokenByAuthorizationCode_ShouldFetchAndCreateIdToken() {
		$this->setClientResponse(self::ID_TOKEN_RESPONSE_BODY);

		$idToken = $this->provider->getIdTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE);

		$expected = self::ID_TOKEN_RESPONSE_ARRAY;
		$actual = null;
		if($idToken instanceof IdTokenStub) {
			$actual = $idToken->options;
		}

		$this->assertEquals($expected, $actual);
	}

	public function test_InvalidCode_getIdTokenByAuthorizationCode_ShouldThrow() {
		$this->setClientResponse(self::AN_ERROR_RESPONSE_BODY);
		$this->response->expects($this->once())
			->method('getStatusCode')
			->willReturn(self::AN_ERROR_RESPONSE_ARRAY['error']['code']);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

		$this->provider->getIdTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE);
	}

	public function test_NoOptions_getRequest_ShouldReturnRequest() {
		$request = new Request(self::A_REQUEST_METHOD, self::A_URI, [], null, '1.1');
		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_REQUEST_METHOD, self::A_URI)
			->willReturn($request);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = $request;
		$actual = $this->provider->getRequest(self::A_REQUEST_METHOD, self::A_URI);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithOptions_getRequest_ShouldReturnRequestWithOptions() {
		$request = new Request(self::A_REQUEST_METHOD, self::A_URI, self::A_REQUEST_OPTIONS_ARRAY['headers'], self::A_REQUEST_OPTIONS_ARRAY['body'], self::A_REQUEST_OPTIONS_ARRAY['version']);

		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_REQUEST_METHOD, self::A_URI)
			->willReturn($request);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = $request;
		$actual = $this->provider->getRequest(self::A_REQUEST_METHOD, self::A_URI, self::A_REQUEST_OPTIONS_ARRAY);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithRequest_getResponse_ShouldReturnResponse(){
		$request = new Request(self::A_REQUEST_METHOD, self::A_URI, [], null, '1.1');

		$this->setClientResponse();

		$expected = $this->response;
		$actual = $this->provider->getResponse($request);

		$this->assertEquals($expected, $actual);
	}
}

class TestableGenericOpenidProvider extends GenericOpenidProvider {

	public function getClientSecret() {
		return $this->clientSecret;
	}

	public function getRedirectUri() {
		return $this->redirectUri;
	}

	public function getNonce() {
		return $this->nonce;
	}

	protected function createIdToken(array $response, GenericOpenidProvider $provider) {
		return new IdTokenStub($response, $provider);
	}
}

class IdTokenStub extends IdToken {

	public $options;
	public $provider;

	public function __construct(array $options = [], GenericOpenidProvider $provider) {
		//parent::__construct($options, $provider);
		$this->options = $options;
		$this->provider = $provider;
	}
}
