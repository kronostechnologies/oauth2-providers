<?php

namespace Kronos\Tests\OAuth2Providers;

use Kronos\OAuth2Providers\Exceptions\InvalidRefreshTokenException;
use Kronos\OAuth2Providers\Exceptions\StateValidationUnsupportedException;
use Kronos\OAuth2Providers\Google\GoogleProvider;
use Kronos\OAuth2Providers\OAuth2Service;
use Kronos\OAuth2Providers\RefreshableOAuth2Service;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class OAuth2ServiceTest extends TestCase
{
    private const AN_ACCESS_TOKEN = 'AN_ACCESS_TOKEN';
    private const A_REFRESH_TOKEN = 'A_REFRESH_TOKEN';
    private const A_URL = 'A_URL';
    private const A_STATE = 'A_STATE';

    /**
     * @var MockObject&AbstractProvider
     */
    private $provider;

    public function test_getResourceOwner_shouldReturnResourceOwnerFromTheProvider()
    {
        $service = $this->givenBasicService();

        $aResourceOwner = $this->createMock(ResourceOwnerInterface::class);
        $anAccessToken = new AccessToken([
            'access_token' => self::AN_ACCESS_TOKEN,
        ]);

        $this->provider
            ->expects(self::once())
            ->method('getResourceOwner')
            ->willReturn($aResourceOwner);

        $actual = $service->getResourceOwner($anAccessToken);

        $this->assertEquals($aResourceOwner, $actual);
    }

    public function test_getAuthorizationUrl_shouldReturnValueFromTheProvider()
    {
        $service = $this->givenBasicService();

        $this->provider
            ->expects(self::once())
            ->method('getAuthorizationUrl')
            ->willReturn(self::A_URL);

        $actual = $service->getAuthorizationUrl();

        $this->assertEquals(self::A_URL, $actual);
    }

    public function test_nonStateAwareProvider_validateState_returnsFalse()
    {
        $service = $this->givenBasicService();

        $this->expectException(StateValidationUnsupportedException::class);

        $service->validateState(self::A_STATE);
    }

    public function test_stateAwareProvider_validateState_delegatesValidationToProvider()
    {
        $service = $this->givenStateAwareProvider();

        $this->provider
            ->expects(self::once())
            ->method('validateState')
            ->willReturn(true);

        $actual = $service->validateState(self::A_STATE);

        $this->assertTrue($actual);
    }

    public function test_refreshableService_getAccessTokenByRefreshToken_delegatesTokenRefreshToProvider()
    {
        $service = $this->givenRefreshableService();

        $anAccessToken = new AccessToken([
            'access_token' => self::AN_ACCESS_TOKEN,
        ]);

        $this->provider
            ->expects(self::once())
            ->method('getAccessToken')
            ->willReturn($anAccessToken);

        $actual = $service->getAccessTokenByRefreshToken(self::A_REFRESH_TOKEN);

        $this->assertEquals($anAccessToken, $actual);
    }

    public function test_emptyRefreshToken_getAccessTokenByRefreshToken_throwsException()
    {
        $service = $this->givenRefreshableService();

        $this->provider
            ->expects(self::never())
            ->method('getAccessToken');

        $this->expectException(InvalidRefreshTokenException::class);

        $service->getAccessTokenByRefreshToken('');
    }

    private function givenBasicService(): OAuth2Service
    {
        $this->provider = $this->createMock(AbstractProvider::class);
        return new OAuth2Service($this->provider);
    }

    private function givenRefreshableService(): RefreshableOAuth2Service
    {
        $this->provider = $this->createMock(AbstractProvider::class);
        return new RefreshableOAuth2Service($this->provider);
    }

    private function givenStateAwareProvider(): OAuth2Service
    {
        $this->provider = $this->createMock(GoogleProvider::class);
        return new OAuth2Service($this->provider);
    }
}
