<?php

namespace Kronos\Tests\OAuth2Providers\Google;

use GuzzleHttp\Client;
use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\Google\GoogleOAuth2Service;
use Kronos\OAuth2Providers\Storage\AccessTokenStorageInterface;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;
use Psr\Http\Message\ResponseInterface;

class GoogleOAuth2ServiceTest extends PHPUnit_Framework_TestCase{

	const A_CLIENT_ID = 'A_CLIENT_ID';
	const A_SECRET = 'A_SECRET';
	const A_REDIRECT_URI = 'A_REDIRECT_URI';

	const A_CUSTOME_OPTION_NAME = 'a_custom_option_name';
	const A_CUSTOME_OPTION_VALUE = 'a_custom_option_value';

	const A_CODE = 'A_CODE';

	const A_REFRESH_TOKEN = 'A_REFRESH_TOKEN';

	/**
	 * @var string
	 */
	private $expectedBaseRessourceOwnerDetailsUrl = 'https://www.googleapis.com/oauth2/v2/userinfo?';

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $httpClient;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $accessTokenStorage;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $anAccessToken;

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	private $httpResponse;

	/**
	 * @var GoogleOAuth2Service
	 */
	private $googleOAuth2Service;

	public function setUp(){
		$this->anAccessToken = $this->getMockWithoutInvokingTheOriginalConstructor(AccessToken::class);
		$this->accessTokenStorage = $this->getMockWithoutInvokingTheOriginalConstructor(AccessTokenStorageInterface::class);

		$this->httpResponse = $this->getMockWithoutInvokingTheOriginalConstructor(ResponseInterface::class);
		$this->httpResponse->method('getBody')->willReturn('{"access_token":"an_access_token"}');

		$this->httpClient = $this->getMockWithoutInvokingTheOriginalConstructor(Client::class);
		$this->httpClient->method('send')->willReturn($this->httpResponse);

		$this->googleOAuth2Service = new GoogleOAuth2Service(self::A_CLIENT_ID,self::A_SECRET,self::A_REDIRECT_URI,$this->accessTokenStorage,['httpClient' => $this->httpClient]);
	}

	public function test_AccessToken_getResourceOwnerDetailsUrl_ShouldReturnOAuth2V2UserinfoUrl(){

		$url = $this->googleOAuth2Service->getResourceOwnerDetailsUrl($this->anAccessToken);

		$this->assertStringStartsWith($this->expectedBaseRessourceOwnerDetailsUrl,$url);
	}

	public function test_askingForAuthorizationUrl_getAuthorizationUrl_ShouldContainsDefaultOption(){
		$url = $this->googleOAuth2Service->getAuthorizationUrl();

		$this->assertContains('approval_prompt=force',$url);
	}

	public function test_askingForAuthorizationUrlWithCustomOptions_getAuthorizationUrl_ShouldContainsOptionsPassedInParameters(){
		$url = $this->googleOAuth2Service->getAuthorizationUrl([self::A_CUSTOME_OPTION_NAME=>self::A_CUSTOME_OPTION_VALUE]);

		$this->assertContains(self::A_CUSTOME_OPTION_NAME.'='.self::A_CUSTOME_OPTION_VALUE,$url);
	}

	public function test_authorizationCode_getAccessTokenByAuthorizationcode_ShouldStoreTokenReceived(){

		$this->accessTokenStorage
			->expects(self::once())
			->method('storeAccessToken');

		$this->googleOAuth2Service->getAccessTokenByAuthorizationcode(self::A_CODE);
	}

	public function test_ARefreshToken_retrieveAccessToken_ShouldReturnAToken(){

		$token = $this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);

		$this->assertInstanceOf(AccessToken::class,$token);
	}

	public function test_ARefreshTokenInStorage_retrieveAccessToken_ShouldRetrieveTokenFromStorage(){
		$this->accessTokenStorage
			->expects(self::once())
			->method('retrieveAccessToken')
			->with(self::A_REFRESH_TOKEN);

		$this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);
	}

	public function test_ARefreshTokenNotInStorage_retrieveAccessToken_ShouldRetrieveTokenFromGoogle(){
		$this->accessTokenStorage
			->method('retrieveAccessToken')
			->willReturn(null);

		$this->httpClient
			->expects(self::once())
			->method('send');

		$this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);
	}

	public function test_AnEmptyRefreshToken_retrieveAccessToken_ShouldThrowInvalidRefreshTokenException(){
		$this->expectException(InvalidRefreshTokenException::class);

		$this->googleOAuth2Service->retrieveAccessToken('');
	}

	public function test_TokenIsInStorage_retrieveAccessToken_ShouldNeverAskGoogle(){
		$this->accessTokenStorage
			->method('retrieveAccessToken')
			->willReturn($this->anAccessToken);

		$this->httpClient
			->expects(self::never())
			->method('send');

		$this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);
	}

	public function test_TokenIsRetreivedByGoogle_retrieveAccessToken_ShouldBeStored(){
		$this->accessTokenStorage
			->method('retrieveAccessToken')
			->willReturn(null);

		$this->accessTokenStorage
			->expects(self::once())
			->method('storeAccessToken');

		$this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);
	}


}