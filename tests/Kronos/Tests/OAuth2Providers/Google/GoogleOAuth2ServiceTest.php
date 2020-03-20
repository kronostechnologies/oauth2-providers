<?php

namespace Kronos\Tests\OAuth2Providers\Google;

use GuzzleHttp\Client;
use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\Google\GoogleOAuth2Service;
use League\OAuth2\Client\Token\AccessToken;
use \PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class GoogleOAuth2ServiceTest extends TestCase {

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
	 * @var MockObject
	 */
	private $httpClient;

	/**
	 * @var MockObject
	 */
	private $anAccessToken;

	/**
	 * @var MockObject
	 */
	private $httpResponse;

	/**
	 * @var GoogleOAuth2Service
	 */
	private $googleOAuth2Service;

	public function setUp(): void
    {
		$this->anAccessToken = $this->createMock(AccessToken::class);

		$this->httpResponse = $this->createMock(ResponseInterface::class);
		$this->httpResponse->method('getBody')->willReturn('{"access_token":"an_access_token"}');

		$this->httpClient = $this->createMock(Client::class);
		$this->httpClient->method('send')->willReturn($this->httpResponse);

		$this->googleOAuth2Service = new GoogleOAuth2Service(self::A_CLIENT_ID,self::A_SECRET,self::A_REDIRECT_URI,['httpClient' => $this->httpClient]);
	}

	public function test_AccessToken_getResourceOwnerDetailsUrl_ShouldReturnOAuth2V2UserinfoUrl(){

		$url = $this->googleOAuth2Service->getResourceOwnerDetailsUrl($this->anAccessToken);

		$this->assertStringStartsWith($this->expectedBaseRessourceOwnerDetailsUrl,$url);
	}

	public function test_askingForAuthorizationUrl_getAuthorizationUrl_ShouldContainsDefaultOption(){
		$url = $this->googleOAuth2Service->getAuthorizationUrl();

		$this->assertStringContainsString('approval_prompt=force',$url);
	}

	public function test_askingForAuthorizationUrl_getAuthorizationUrl_ShouldContainsStateParameterWithValidSalt(){
		$url = $this->googleOAuth2Service->getAuthorizationUrl();

		$this->assertRegExp('/state=[a-z0-9]{8}_[a-z0-9]+/',$url);
	}

	public function test_askingForAuthorizationUrlWithCustomOptions_getAuthorizationUrl_ShouldContainsOptionsPassedInParameters(){
		$url = $this->googleOAuth2Service->getAuthorizationUrl([self::A_CUSTOME_OPTION_NAME=>self::A_CUSTOME_OPTION_VALUE]);

		$this->assertStringContainsString(self::A_CUSTOME_OPTION_NAME.'='.self::A_CUSTOME_OPTION_VALUE,$url);
	}

	public function test_ARefreshToken_retrieveAccessToken_ShouldReturnAToken(){

		$token = $this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);

		$this->assertInstanceOf(AccessToken::class,$token);
	}

	public function test_retrieveAccessToken_ShouldRetrieveTokenFromGoogle(){
		$this->httpClient
			->expects(self::once())
			->method('send');

		$this->googleOAuth2Service->retrieveAccessToken(self::A_REFRESH_TOKEN);
	}

	public function test_AnEmptyRefreshToken_retrieveAccessToken_ShouldThrowInvalidRefreshTokenException(){
		$this->expectException(InvalidRefreshTokenException::class);

		$this->googleOAuth2Service->retrieveAccessToken('');
	}
}
