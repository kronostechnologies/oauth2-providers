<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\State\NonceServiceInterface;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenValidator;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use \PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class IdTokenValidatorTest extends TestCase
{

    const A_PARSED_CLAIMS_ARRAY = [
        'azp' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'sub' => '107963962148033347052',
        'at_hash' => 'Yv0WXK12-Ov59muE0pUzqw',
        'nonce' => '6664b3eb64d51bb14201580a6d26133d73d3a9665fdc5bc835becb67ebb41dac_0cc53e6f653397930fde563275f42868fc0f9978',
        'iss' => 'https://accounts.google.com',
        'iat' => 1505328697,
        'exp' => 1505332297
    ];

    const A_CLIENT_ID = '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com';
    const AN_ISSUER = 'https://accounts.google.com';
    const A_NONCE = '6664b3eb64d51bb14201580a6d26133d73d3a9665fdc5bc835becb67ebb41dac_0cc53e6f653397930fde563275f42868fc0f9978';

    /**
     * @var MockObject
     */
    private $hashService;

    public function setUp(): void
    {
        $this->hashService = $this->getMockBuilder(NonceServiceInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
    }

    public function test_NoHashService_New_ShouldCreateNewHashService()
    {
        $validator = new TestableIdTokenValidator();

        $expected = SessionBasedHashService::class;
        $actual = get_class($validator->getHashService());

        $this->assertEquals($expected, $actual);
    }

    public function testWithHashService_New_ShouldSetProvidedHashService()
    {
        $validator = new TestableIdTokenValidator($this->hashService);

        $expected = $this->hashService;
        $actual = $validator->getHashService();

        $this->assertEquals($expected, $actual);
    }

    public function test_ValidParams_validateIdTokenClaims_ShouldDoNothing()
    {
        $this->hashService->expects($this->once())
            ->method('validateNonce')
            ->with(self::A_NONCE)
            ->willReturn(true);

        $validator = new TestableIdTokenValidator($this->hashService);
        $validator->validateIdTokenClaims(self::A_PARSED_CLAIMS_ARRAY, self::A_CLIENT_ID, self::AN_ISSUER,
            self::A_NONCE);

        $this->assertTrue(true);
    }

    public function test_InvalidClientId_validateIdTokenClaims_ShouldThrowException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The audience is invalid!');

        $validator = new TestableIdTokenValidator($this->hashService);
        $validator->validateIdTokenClaims(self::A_PARSED_CLAIMS_ARRAY, '', self::AN_ISSUER, self::A_NONCE);
    }

    public function test_InvalidIssuer_validateIdTokenClaims_ShouldThrowException()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The issuer is invalid!');

        $validator = new TestableIdTokenValidator($this->hashService);
        $validator->validateIdTokenClaims(self::A_PARSED_CLAIMS_ARRAY, self::A_CLIENT_ID, '', self::A_NONCE);
    }

    public function test_InvalidNonce_validateIdTokenClaims_ShouldThrowException()
    {
        $this->hashService->expects($this->once())
            ->method('validateNonce')
            ->with(self::A_NONCE)
            ->willReturn(false);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The nonce is invalid!');

        $validator = new TestableIdTokenValidator($this->hashService);
        $validator->validateIdTokenClaims(self::A_PARSED_CLAIMS_ARRAY, self::A_CLIENT_ID, self::AN_ISSUER, '');
    }
}

class TestableIdTokenValidator extends IdTokenValidator
{

    public function getHashService()
    {
        return $this->nonceValidator;
    }
}
