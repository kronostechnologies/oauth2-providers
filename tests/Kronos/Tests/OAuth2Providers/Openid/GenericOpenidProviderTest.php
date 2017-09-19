<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use BadMethodCallException;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken;
use Kronos\OAuth2Providers\Openid\OpenidUser;
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

	const A_KEYS_RESPONSE_BODY = '{
 "keys": [
  {
   "kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "288c8449ce6038da2beca551dd5b7fe1a8a603a2",
   "n": "lQ8I4NKbTgTCXSsDWTPPl4W7DWkj201Se7G45NXe4l9dQ09WZ767FOcSfeVR-HQrCKU0MwA2CW78MGtWhSepwgkjGSXcFg15X9Q8RVxbptN0zXku2TVubjlh-Ff714cmNxSqJwylnBXfdSYzGLYwZDdmnngGPC8_WNOrdTKHlHG5wH9wMRdzBNC1CD2lndZD16X6PMdIBwBp7_qxmRp0VIVaBe7AHx4iOvY8t6ITjueU0JfAKAwptfqIUCpzcnKYLuvt_Yb4JI5f3XB3wLwsEXeVbAKdk-E8cHbPObQovAff4q3rbEoBEXT1HO1VhNYN6FuLiR3_ESycgpOkpjkg8w",
   "e": "AQAB"
  },
	{
		"kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "06dcba0c1a62963f8d069ab486af931b0036004a",
   "n": "1ZJ0vMEk1zqDvxd2Rq2CzbRnR_BXS_QhCnVCVsMl4vJAPjeavccCkLxK_alM5uu-QFHwBtafdJJS1poATPWe7Rmvo94TuUz0cHoSW38JfmhEqypZ-SbSNNA903dX2dxpZZOPLpbw34un6txSue8XQo-VHuSge5X0PYI03H3aOA0yKoc5RzeINmJbsys09vHIKHywGayn0CMO80L0iCNMCHwGa3PiQLDO6k1Ob99ldBLUOvSw3ymJoIuvVftq-wDpkwZ1p_ouPCfPB7lA5uJTsrjpRv3Uj6-PVL4yIF8RrCO48Afw2LbaNluwTucFF5PHDB_hXvVqThIvKjP_t2zS-Q",
   "e": "AQAB"
  },
	{
		"kty": "RSA",
   "alg": "RS256",
   "use": "sig",
   "kid": "303b2855a91438570ca72850491741e96bd99ef8",
   "n": "xjHhLN2489-vNqJrOTWbNS-f1H810owFC-bZii1eAZ3UfAnB92V9lPsU_x9IKSLCLrsGIMfVG9Zs-m-7g8xGQ_tUrCnHZF0CWgGt14LV53caoSIh7jXSz18zsTMIF0U5Fn1y4gARAp2KHh9qnuK9Nd5dnvZ9MC2vkknDkGjv8_9pKpo-SRjiFp-U-rprpcbwR_lRw2_Kk8IIZY7MLiDnkfTxAnPOJz7KNezpUPElzO9efyd1E7vjbXrHvu2BybMdNfqSGu3Mmx23LzFL3pfCsjTycgxQACSlAS3DVxeQWygbOyz27wYo1F1P7nsKk0p-Gjfk_izQhuOz4Z73MHdrLQ",
   "e": "AQAB"
  }
]
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
-----END PUBLIC KEY-----",
     '06dcba0c1a62963f8d069ab486af931b0036004a' => "-----BEGIN PUBLIC KEY-----\r
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZJ0vMEk1zqDvxd2Rq2C\r
zbRnR/BXS/QhCnVCVsMl4vJAPjeavccCkLxK/alM5uu+QFHwBtafdJJS1poATPWe\r
7Rmvo94TuUz0cHoSW38JfmhEqypZ+SbSNNA903dX2dxpZZOPLpbw34un6txSue8X\r
Qo+VHuSge5X0PYI03H3aOA0yKoc5RzeINmJbsys09vHIKHywGayn0CMO80L0iCNM\r
CHwGa3PiQLDO6k1Ob99ldBLUOvSw3ymJoIuvVftq+wDpkwZ1p/ouPCfPB7lA5uJT\r
srjpRv3Uj6+PVL4yIF8RrCO48Afw2LbaNluwTucFF5PHDB/hXvVqThIvKjP/t2zS\r
+QIDAQAB\r
-----END PUBLIC KEY-----",
     '303b2855a91438570ca72850491741e96bd99ef8' => "-----BEGIN PUBLIC KEY-----\r
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjHhLN2489+vNqJrOTWb\r
NS+f1H810owFC+bZii1eAZ3UfAnB92V9lPsU/x9IKSLCLrsGIMfVG9Zs+m+7g8xG\r
Q/tUrCnHZF0CWgGt14LV53caoSIh7jXSz18zsTMIF0U5Fn1y4gARAp2KHh9qnuK9\r
Nd5dnvZ9MC2vkknDkGjv8/9pKpo+SRjiFp+U+rprpcbwR/lRw2/Kk8IIZY7MLiDn\r
kfTxAnPOJz7KNezpUPElzO9efyd1E7vjbXrHvu2BybMdNfqSGu3Mmx23LzFL3pfC\r
sjTycgxQACSlAS3DVxeQWygbOyz27wYo1F1P7nsKk0p+Gjfk/izQhuOz4Z73MHdr\r
LQIDAQAB\r
-----END PUBLIC KEY-----"
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
	const A_GET_REQUEST_METHOD = 'GET';
	const A_URI = 'https://example.com';
	const AN_EXCEPTION_MESSAGE = 'AN EXCEPTION OCCURRED';
	const A_TOKEN_STRING = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2ZGNiYTBjMWE2Mjk2M2Y4ZDA2OWFiNDg2YWY5MzFiMDAzNjAwNGEifQ.eyJhenAiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDc5NjM5NjIxNDgwMzMzNDcwNTIiLCJhdF9oYXNoIjoiWXYwV1hLMTItT3Y1OW11RTBwVXpxdyIsIm5vbmNlIjoiNjY2NGIzZWI2NGQ1MWJiMTQyMDE1ODBhNmQyNjEzM2Q3M2QzYTk2NjVmZGM1YmM4MzViZWNiNjdlYmI0MWRhY18wY2M1M2U2ZjY1MzM5NzkzMGZkZTU2MzI3NWY0Mjg2OGZjMGY5OTc4IiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTA1MzI4Njk3LCJleHAiOjE1MDUzMzIyOTd9.piVQuDW0lK1SXSmUylLkdcHxLwE7IL5BpIboAv4i6O1qIe9KUcJFIE2YCUCQIAw1xnosr0o-KQ_m-9UDG401WUI4t8tO-IRhpufYvfwhNYexTclhD3b4TZQUATmhe0mxfZiYWWjnZhO-crG5kc1l9iDFO8Yu7UefpHIbjCVWtkC7UEOJXlzsKizTsU3FuseRMCOMD1PNEhS5iOILLce-O0VzdTtUSLvnUp15nEvHaXPLvLqbhGGCfabqfVEF1QuQ_APEp3WBhVgvhOy5aD0n0k7CS4yIz8NE-m9tzuMGkY8ujZAQDk_zV5nLx4ZdsdUMbBVMJxEabHVg0WdbKfBGPg';
	const AN_EMPTY_STRING_ARRAY = [''];

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

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|BadResponseException
	 */
	protected $badResponseException;

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
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, [], null, '1.1');
		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_GET_REQUEST_METHOD, self::A_URI)
			->willReturn($request);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = $request;
		$actual = $this->provider->getRequest(self::A_GET_REQUEST_METHOD, self::A_URI);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithOptions_getRequest_ShouldReturnRequestWithOptions() {
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, self::A_REQUEST_OPTIONS_ARRAY['headers'], self::A_REQUEST_OPTIONS_ARRAY['body'], self::A_REQUEST_OPTIONS_ARRAY['version']);

		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_GET_REQUEST_METHOD, self::A_URI)
			->willReturn($request);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = $request;
		$actual = $this->provider->getRequest(self::A_GET_REQUEST_METHOD, self::A_URI, self::A_REQUEST_OPTIONS_ARRAY);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithSuccessfulRequest_getResponse_ShouldReturnResponse(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, [], null, '1.1');

		$this->setClientResponse();

		$expected = $this->response;
		$actual = $this->provider->getResponse($request);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithFailedRequest_getResponse_ShouldLetExceptionThrough(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, [], null, '1.1');

		$exception = new RequestException(self::AN_EXCEPTION_MESSAGE, $request);
		$this->httpClient->expects($this->once())
			->method('send')
			->willThrowException($exception);

		$this->expectException(RequestException::class);
		$this->expectExceptionMessage(self::AN_EXCEPTION_MESSAGE);

		$this->provider->getResponse($request);
	}

	public function test_WithSuccessfulRequest_getParsedResponse_ShouldReturnParsedResponse(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, [], null, '1.1');

		$this->setClientResponse(self::ID_TOKEN_RESPONSE_BODY);

		$expected = self::ID_TOKEN_RESPONSE_ARRAY;
		$actual = $this->provider->getParsedResponse($request);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithFailedRequest_getParsedResponse_ShouldReturnParsedResponseError(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::A_URI, [], null, '1.1');

		$this->badResponseException = $this->getMockBuilder(BadResponseException::class)
			->disableOriginalConstructor()
			->setMethods(['getResponse'])
			->getMock();
		$this->badResponseException->expects($this->once())
			->method('getResponse')
			->willReturn($this->response);

		$this->httpClient->expects($this->once())
			->method('send')
			->willThrowException($this->badResponseException);
		$this->response->expects($this->once())
			->method('getBody')
			->willReturn(self::ID_TOKEN_RESPONSE_BODY);

		$expected = self::ID_TOKEN_RESPONSE_ARRAY;
		$actual = $this->provider->getParsedResponse($request);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithIdToken_getResourceOwner_ShouldReturnNewOpenidUser(){
		$token = new IdTokenStub(self::A_REQUEST_OPTIONS_ARRAY, $this->provider);
		$openidUser = $this->provider->getResourceOwner($token);

		$expected = $token;
		$actual = null;
		if($openidUser instanceof OpenidUserStub) {
			$actual = $openidUser->id_token;
		}

		$this->assertEquals($expected, $actual);
	}

	public function test_WithoutToken_getHeaders_ShouldReturnDefaultHeaders(){
		$expected = [];
		$actual = $this->provider->getHeaders();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithStringToken_getHeaders_ShouldReturnAuthorizationBearerWithToken(){
		$expected = ['Authorization' => 'Bearer ' . self::A_TOKEN_STRING];
		$actual = $this->provider->getHeaders(self::A_TOKEN_STRING);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithObjectToken_getHeaders_ShouldReturnAuthorizationBearerWithTokenToString(){
		$token = new IdTokenStub(self::A_REQUEST_OPTIONS_ARRAY, $this->provider);

		$expected = ['Authorization' => 'Bearer ' . $token];
		$actual = $this->provider->getHeaders($token);

		$this->assertEquals($expected, $actual);
	}

	public function test_WithUrlAndSuccessfulResponse_getJwtVerificationKeys_ShouldReturnKeysArray(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::OPENID_CONFIG_ARRAY['jwks_uri'], [], null, '1.1');
		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_GET_REQUEST_METHOD, self::OPENID_CONFIG_ARRAY['jwks_uri'])
			->willReturn($request);

		$this->setClientResponse(self::A_KEYS_RESPONSE_BODY);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = self::A_DECODED_KEYS_ARRAY;
		$actual = $this->provider->getJwtVerificationKeys();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithUrlAndErrorResponse_getJwtVerificationKeys_ShouldReturnEmptyArray(){
		$request = new Request(self::A_GET_REQUEST_METHOD, self::OPENID_CONFIG_ARRAY['jwks_uri'], [], null, '1.1');
		$this->requestFactory = $this->getMockBuilder(RequestFactory::class)
			->setMethods(['getRequestWithOptions'])
			->getMock();
		$this->requestFactory->expects($this->once())
			->method('getRequestWithOptions')
			->with(self::A_GET_REQUEST_METHOD, self::OPENID_CONFIG_ARRAY['jwks_uri'])
			->willReturn($request);

		$this->badResponseException = $this->getMockBuilder(BadResponseException::class)
			->disableOriginalConstructor()
			->setMethods(['getResponse'])
			->getMock();
		$this->badResponseException->expects($this->once())
			->method('getResponse')
			->willReturn($this->response);

		$this->httpClient->expects($this->once())
			->method('send')
			->willThrowException($this->badResponseException);
		$this->response->expects($this->once())
			->method('getBody')
			->willReturn(self::ID_TOKEN_RESPONSE_BODY);

		$this->collaborators = ['grantFactory' => $this->grantFactory, 'requestFactory' => $this->requestFactory, 'httpClient' => $this->httpClient];
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = [];
		$actual = $this->provider->getJwtVerificationKeys();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithUrl_getVerificationKeysUrl_ShouldReturnKeysUrl(){
		$expected = self::OPENID_CONFIG_ARRAY['jwks_uri'];
		$actual = $this->provider->getVerificationKeysUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithoutUrl_getVerificationKeysUrl_ShouldReturnEmptyString(){
		$config = self::OPENID_CONFIG_ARRAY;
		unset($config['jwks_uri']);
		$this->provider->setOpenidConfig($config);

		$expected = '';
		$actual = $this->provider->getVerificationKeysUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithConfig_getOpenidConfiguration_ShouldReturnOpenidConfig(){
		$expected = self::OPENID_CONFIG_ARRAY;
		$actual = $this->provider->getOpenidConfiguration();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithUrl_getOpenidConfigurationUrl_ShouldReturnOpenidConfigUrl(){
		$expected = self::VALID_OPTIONS['openidConfigurationUrl'];
		$actual = $this->provider->getOpenidConfigurationUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithUrl_getOpenidConfigurationUrl_ShouldReturnNull(){
		$this->options = self::VALID_OPTIONS;
		unset($this->options['openidConfigurationUrl']);
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = '';
		$actual = $this->provider->getVerificationKeysUrl();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithoutState_getState_ShouldReturnNull(){
		$expected = null;
		$actual = $this->provider->getState();

		$this->assertEquals($expected, $actual);
	}

	public function test_WithState_getState_ShouldReturnState(){
		$this->options['state'] = self::A_STATE_STRING;
		$this->provider = new TestableGenericOpenidProvider($this->options, $this->collaborators);

		$expected = self::A_STATE_STRING;
		$actual = $this->provider->getState();

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

	public function getState() {
		return $this->state;
	}

	protected function createIdToken(array $response, GenericOpenidProvider $provider) {
		return new IdTokenStub($response, $provider);
	}

	protected function createResourceOwner(IdToken $token) {
		return new OpenidUserStub($token);
	}

	public function setOpenidConfig($config = []){
		$this->setOpenidConfiguration($config);
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

class OpenidUserStub extends OpenidUser {

	public $id_token;
}
