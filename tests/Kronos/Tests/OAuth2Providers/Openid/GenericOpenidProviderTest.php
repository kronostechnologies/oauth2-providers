<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use BadMethodCallException;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;
use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\Openid\OpenidProviderCollaborators;
use Kronos\OAuth2Providers\Openid\OpenidProviderOptions;
use Kronos\OAuth2Providers\SessionBasedHashService;
use League\OAuth2\Client\Grant\Exception\InvalidGrantException;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\RequestFactory;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\ResponseInterface;

class GenericOpenidProviderTest extends PHPUnit_Framework_TestCase {

	const VALID_OPTIONS = [
		'clientId' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
		'clientSecret' => 'qBqmkV1PIrDCbEdbMRU9lEoh',
		'redirectUri' => 'https://dev.kronos-dev.com/login/api/auth/ia/callback',
		'openidConfigurationUrl' => 'https://accounts.google.com/.well-known/openid-configuration'
	];

	const OPENID_CONFIG_ARRAY = [
		'issuer' => 'https://accounts.google.com',
		'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
		'token_endpoint' => 'https://www.googleapis.com/oauth2/v4/token',
		'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
	];

	const OPENID_CONFIG_RESPONSE_BODY = '{
	  "issuer": "https://accounts.google.com",
	  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
	  "token_endpoint": "https://www.googleapis.com/oauth2/v4/token",
	  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"
	}';

	const ID_TOKEN_RESPONSE_BODY = '{
      "id_token": "' . self::A_VALID_TOKEN . '"
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

	const A_KEYS_RESPONSE_BODY = '{
      "keys": [{"kty": "RSA",
			    "alg": "RS256",
			    "use": "sig",
			    "kid": "288c8449ce6038da2beca551dd5b7fe1a8a603a2",
			    "n": "lQ8I4NKbTgTCXSsDWTPPl4W7DWkj201Se7G45NXe4l9dQ09WZ767FOcSfeVR-HQrCKU0MwA2CW78MGtWhSepwgkjGSXcFg15X9Q8RVxbptN0zXku2TVubjlh-Ff714cmNxSqJwylnBXfdSYzGLYwZDdmnngGPC8_WNOrdTKHlHG5wH9wMRdzBNC1CD2lndZD16X6PMdIBwBp7_qxmRp0VIVaBe7AHx4iOvY8t6ITjueU0JfAKAwptfqIUCpzcnKYLuvt_Yb4JI5f3XB3wLwsEXeVbAKdk-E8cHbPObQovAff4q3rbEoBEXT1HO1VhNYN6FuLiR3_ESycgpOkpjkg8w",
			    "e": "AQAB"
			   }]
    }';

	const A_DECODED_KEYS_ARRAY = [
		'288c8449ce6038da2beca551dd5b7fe1a8a603a2' => "-----BEGIN PUBLIC KEY-----\r
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlQ8I4NKbTgTCXSsDWTPP\r
l4W7DWkj201Se7G45NXe4l9dQ09WZ767FOcSfeVR+HQrCKU0MwA2CW78MGtWhSep\r
wgkjGSXcFg15X9Q8RVxbptN0zXku2TVubjlh+Ff714cmNxSqJwylnBXfdSYzGLYw\r
ZDdmnngGPC8/WNOrdTKHlHG5wH9wMRdzBNC1CD2lndZD16X6PMdIBwBp7/qxmRp0\r
VIVaBe7AHx4iOvY8t6ITjueU0JfAKAwptfqIUCpzcnKYLuvt/Yb4JI5f3XB3wLws\r
EXeVbAKdk+E8cHbPObQovAff4q3rbEoBEXT1HO1VhNYN6FuLiR3/ESycgpOkpjkg\r
8wIDAQAB\r
-----END PUBLIC KEY-----"
	];

	const A_VALID_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MzUwMjgyODgwMCwiZXhwIjo0MTAyMzU4NDAwLCJpYXQiOjE1MDY1Mjk3NDQsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.xZ90KU2HTm1Ok-14f64I1OGuc7RIn5kzkzVsFVsXPchoHA4-oj8TWWszvkzmxhe40JcVRboRiaCSszGp-kDdVt85bVR3IBGWNAdP9Lt_L9k9WLranLjpN-0g7_F-Zx40e6vYUTV5d_Z-t2NuagFSomWa1NgvAiQSxFbVZ2FkeD0YKXW0CyViLWFHlab0m3cmYjE1T_wxNRDpZh0_L7I6HrwaGo7VYadSwteodCrsSLQpiPly0m27SJdlIdhF7vsYzf-xZisVW9sBCJuicYgZHxgk3x4oWEy5hYlzCy0ucdRZbIrRUYycgcJJPAhXe0LZbG6uAAsByqm-meZ4RJvCew';
	const A_STATE_STRING = 'SOME_STATE_1234';
	const A_NONCE_STRING = 'SOME_NONCE_1234';
	const DEFAULT_OPENID_SCOPE = 'openid';
	const DEFAULT_RESPONSE_TYPE = 'code';
	const DEFAULT_APPROVAL_PROMPT = 'auto';
	const AN_AUTHORIZATION_GRANT = 'authorization_code';
	const AN_AUTHORIZATION_CODE = 'some_code_1234';
	const AN_AUTHORIZATION_CODE_ARRAY = ['code' => self::AN_AUTHORIZATION_CODE];
	const AN_INVALID_GRANT_STRING = 'InvalidGrant';

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
	 * @var PHPUnit_Framework_MockObject_MockObject|SessionBasedHashService
	 */
	protected $hashService;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|IdTokenFactory
	 */
	protected $idTokenFactory;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|OpenidProviderOptions
	 */
	protected $options;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|OpenidProviderCollaborators
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
	 * @var PHPUnit_Framework_MockObject_MockObject|BadResponseException
	 */
	protected $badResponseException;


	public function setUp() {
		$this->grantFactory = $this->getMockBuilder(GrantFactory::class)
			->setMethods(null)
			->getMock();

		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(null)
			->getMock();

		$this->httpClient = $this->getMockBuilder(HttpClient::class)
			->setMethods(['send'])
			->getMock();

		$this->hashService = $this->getMockBuilder(SessionBasedHashService::class)
			->setMethods(['getSessionBasedHash', 'validateSessionBasedHash'])
			->getMock();

		$this->idTokenFactory = $this->getMockBuilder(IdTokenFactory::class)
			->setMethods(['createIdToken'])
			->getMock();

		$this->options = new OpenidProviderOptions(self::VALID_OPTIONS);

		$this->collaborators = new OpenidProviderCollaborators($this->grantFactory, $this->requestFactory, $this->httpClient, $this->hashService, $this->idTokenFactory);

		$this->response = $this->getMockForAbstractClass(ResponseInterface::class);
	}


	private function buildAuthorizationUrl($state, $nonce, $scope = self::DEFAULT_OPENID_SCOPE) {
		$authorizationUrlValues = [
			'uri' => self::OPENID_CONFIG_ARRAY['authorization_endpoint'],
			'state' => $state,
			'nonce' => $nonce,
			'response_type' => self::DEFAULT_RESPONSE_TYPE,
			'approval_prompt' => self::DEFAULT_APPROVAL_PROMPT,
			'scope' => $scope,
			'redirect_uri' => urlencode(self::VALID_OPTIONS['redirectUri']),
			'client_id' => self::VALID_OPTIONS['clientId']
		];

		$authorizationUrl = array_shift($authorizationUrlValues) . '?';
		foreach($authorizationUrlValues as $key => $value) {
			$authorizationUrl .= $key . '=' . $value . '&';
		}

		return rtrim($authorizationUrl, '&');
	}


	public function test_OptionsAndCollaborators_New_ShouldFetchOpenidConfig() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturn(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->once())
			->method('send')
			->willReturn($this->response);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = self::OPENID_CONFIG_ARRAY;
		$actual = $this->provider->getOpenidConfiguration();
		$this->assertEquals($expected, $actual);
	}

	public function test__getAuthorizationUrl_ShouldReturnDefaultAuthorizationUrlWithRandomNonceAndStateAndDefaultScope() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturn(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->once())
			->method('send')
			->willReturn($this->response);

		$this->hashService->expects($this->exactly(2))
			->method('getSessionBasedHash')
			->willReturnOnConsecutiveCalls(self::A_STATE_STRING, self::A_NONCE_STRING);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$actual = $this->provider->getAuthorizationUrl();
		$expected = $this->buildAuthorizationUrl(self::A_STATE_STRING, self::A_NONCE_STRING);

		$this->assertEquals($expected, $actual);
	}

	public function test_GrantAndCode_getIdToken_ShouldFetchAndCreateIdToken() {
		$this->response->expects($this->exactly(3))
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY, self::ID_TOKEN_RESPONSE_BODY, self::A_KEYS_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(3))
			->method('send')
			->willReturn($this->response);

		$testIdToken = new IdToken(self::ID_TOKEN_RESPONSE_ARRAY, 'sub');

		$this->idTokenFactory->expects($this->once())
			->method('createIdToken')
			->with(self::A_VALID_TOKEN, self::A_DECODED_KEYS_ARRAY, self::VALID_OPTIONS['clientId'], self::OPENID_CONFIG_ARRAY['issuer'])
			->willReturn($testIdToken);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$idToken = $this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);

		$expected = $testIdToken;
		$actual = $idToken;

		$this->assertEquals($expected, $actual);
	}


	public function test_GrantNoCode_getIdToken_ShouldThrow() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(1))
			->method('send')
			->willReturn($this->response);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->expectException(BadMethodCallException::class);
		$this->expectExceptionMessage('Required parameter not passed: "code"');

		$this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT);
	}

	public function test_InvalidGrant_getIdToken_ShouldThrow() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(1))
			->method('send')
			->willReturn($this->response);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->expectException(InvalidGrantException::class);
		$this->expectExceptionMessage('Grant "League\OAuth2\Client\Grant\\' . self::AN_INVALID_GRANT_STRING . '" must extend AbstractGrant');

		$this->provider->getIdToken(self::AN_INVALID_GRANT_STRING);
	}

	public function test_InvalidCode_getIdToken_ShouldThrow() {
		$this->response->expects($this->exactly(2))
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY, self::AN_ERROR_RESPONSE_BODY);
		$this->response->expects($this->once())
			->method('getStatusCode')
			->willReturn(self::AN_ERROR_RESPONSE_ARRAY['error']['code']);
		$this->httpClient->expects($this->exactly(2))
			->method('send')
			->willReturn($this->response);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

		$this->provider->getIdToken(self::AN_AUTHORIZATION_GRANT, self::AN_AUTHORIZATION_CODE_ARRAY);
	}

	public function test_WithCode_getIdTokenByAuthorizationCode_ShouldFetchAndCreateIdToken() {
		$this->response->expects($this->exactly(3))
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY, self::ID_TOKEN_RESPONSE_BODY, self::A_KEYS_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(3))
			->method('send')
			->willReturn($this->response);

		$testIdToken = new IdToken(self::ID_TOKEN_RESPONSE_ARRAY, 'sub');

		$this->idTokenFactory->expects($this->once())
			->method('createIdToken')
			->with(self::A_VALID_TOKEN, self::A_DECODED_KEYS_ARRAY, self::VALID_OPTIONS['clientId'], self::OPENID_CONFIG_ARRAY['issuer'])
			->willReturn($testIdToken);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$idToken = $this->provider->getIdTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE_ARRAY['code']);

		$expected = $testIdToken;
		$actual = $idToken;

		$this->assertEquals($expected, $actual);
	}

	public function test_InvalidCode_getIdTokenByAuthorizationCode_ShouldThrow() {
		$this->response->expects($this->exactly(2))
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY, self::AN_ERROR_RESPONSE_BODY);
		$this->response->expects($this->once())
			->method('getStatusCode')
			->willReturn(self::AN_ERROR_RESPONSE_ARRAY['error']['code']);
		$this->httpClient->expects($this->exactly(2))
			->method('send')
			->willReturn($this->response);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->expectException(IdentityProviderException::class);
		$this->expectExceptionMessage(self::AN_ERROR_RESPONSE_ARRAY['error']['message']);

		$this->provider->getIdTokenByAuthorizationCode(self::AN_AUTHORIZATION_CODE_ARRAY['code']);
	}

	public function test_ValidState_validateState_ShouldReturnTrue() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(1))
			->method('send')
			->willReturn($this->response);
		$this->hashService->expects($this->once())
			->method('validateSessionBasedHash')
			->with(self::A_STATE_STRING)
			->willReturn(true);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->assertTrue($this->provider->validateSate(self::A_STATE_STRING));
	}

	public function test_InvalidState_validateState_ShouldReturnFalse() {
		$this->response->expects($this->once())
			->method('getBody')
			->willReturnOnConsecutiveCalls(self::OPENID_CONFIG_RESPONSE_BODY);
		$this->httpClient->expects($this->exactly(1))
			->method('send')
			->willReturn($this->response);
		$this->hashService->expects($this->once())
			->method('validateSessionBasedHash')
			->with(self::A_STATE_STRING)
			->willReturn(false);

		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$this->assertFalse($this->provider->validateSate(self::A_STATE_STRING));
	}
}

class TestableGenericOpenidProvider extends GenericOpenidProvider {

	public function getOpenidConfiguration() {
		return $this->openidConfiguration;
	}
}
