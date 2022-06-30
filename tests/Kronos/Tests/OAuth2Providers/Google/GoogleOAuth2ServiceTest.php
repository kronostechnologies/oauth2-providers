<?php

namespace Kronos\Tests\OAuth2Providers\Google;

use GuzzleHttp\Client;
use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\Google\GoogleProvider;
use Kronos\OAuth2Providers\RefreshableOAuth2Service;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

class GoogleOAuth2ServiceTest extends TestCase
{
    private const A_CLIENT_ID = 'A_CLIENT_ID';
    private const A_SECRET = 'A_SECRET';
    private const A_REDIRECT_URI = 'A_REDIRECT_URI';
    private const A_CUSTOME_OPTION_NAME = 'a_custom_option_name';
    private const A_CUSTOME_OPTION_VALUE = 'a_custom_option_value';
    private const A_REFRESH_TOKEN = 'A_REFRESH_TOKEN';

    /**
     * @var MockObject&Client
     */
    private $httpClient;

    /**
     * @var MockObject&AccessToken
     */
    private $anAccessToken;

    /**
     * @var MockObject&ResponseInterface
     */
    private $httpResponse;

    /**
     * @var RefreshableOAuth2Service
     */
    private $googleOAuth2Service;

    public function setUp(): void
    {
        $this->anAccessToken = $this->createMock(AccessToken::class);

        $this->httpResponse = $this->createMock(ResponseInterface::class);
        $this->httpResponse->method('getBody')->willReturn('{"access_token":"an_access_token"}');

        $this->httpClient = $this->createMock(Client::class);
        $this->httpClient->method('send')->willReturn($this->httpResponse);

        $provider = new GoogleProvider([
            'clientId' => self::A_CLIENT_ID,
            'clientSecret' => self::A_SECRET,
            'redirectUri' => self::A_REDIRECT_URI,
        ], [
            'httpClient' => $this->httpClient,
        ]);

        $this->googleOAuth2Service = new RefreshableOAuth2Service($provider);
    }

    public function test_askingForAuthorizationUrl_getAuthorizationUrl_ShouldContainsDefaultOption()
    {
        $url = $this->googleOAuth2Service->getAuthorizationUrl();

        $this->assertStringContainsString('prompt=consent', $url);
    }

    public function test_askingForAuthorizationUrl_getAuthorizationUrl_ShouldContainsStateParameterWithValidSalt()
    {
        $url = $this->googleOAuth2Service->getAuthorizationUrl();

        $this->assertMatchesRegularExpression('/state=[a-z0-9]{8}_[a-z0-9]+/', $url);
    }

    public function test_askingForAuthorizationUrlWithCustomOptions_getAuthorizationUrl_ShouldContainsOptionsPassedInParameters()
    {
        $url = $this->googleOAuth2Service->getAuthorizationUrl([
            self::A_CUSTOME_OPTION_NAME => self::A_CUSTOME_OPTION_VALUE,
        ]);

        $this->assertStringContainsString(self::A_CUSTOME_OPTION_NAME . '=' . self::A_CUSTOME_OPTION_VALUE, $url);
    }

    public function test_ARefreshToken_getAccessTokenByRefreshToken_ShouldReturnAToken()
    {
        $token = $this->googleOAuth2Service->getAccessTokenByRefreshToken(self::A_REFRESH_TOKEN);

        $this->assertInstanceOf(AccessToken::class, $token);
    }

    public function test_getAccessTokenByRefreshToken_ShouldRetrieveTokenFromGoogle()
    {
        $this->httpClient
            ->expects(self::once())
            ->method('send');

        $this->googleOAuth2Service->getAccessTokenByRefreshToken(self::A_REFRESH_TOKEN);
    }

    public function test_AnEmptyRefreshToken_getAccessTokenByRefreshToken_ShouldThrowInvalidRefreshTokenException()
    {
        $this->expectException(InvalidRefreshTokenException::class);

        $this->googleOAuth2Service->getAccessTokenByRefreshToken('');
    }
}
