<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use InvalidArgumentException;
use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use \PHPUnit\Framework\MockObject\MockObject;
use RuntimeException;

class IdTokenTestCase extends \PHPUnit\Framework\TestCase
{

    const VALID_JWT_KEYS = ['keys' => '123456'];
    const USER_ID = '107963962148033347052';
    const PARSED_CLAIMS = [
        'azp' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'sub' => '107963962148033347052',
        'at_hash' => 'Yv0WXK12-Ov59muE0pUzqw',
        'nonce' => '6664b3eb64d51bb14201580a6d26133d73d3a9665fdc5bc835becb67ebb41dac_0cc53e6f653397930fde563275f42868fc0f9978',
        'iss' => 'https://accounts.google.com',
        'iat' => 1505328697,
        'exp' => 1505332297
    ];
    const OPENID_CONFIGURATION = ['issuer' => 'https://accounts.google.com'];
    const VALID_CLIENT_ID = '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com';
    const INVALID_CLIENT_ID = '';
    const A_VALID_TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2ZGNiYTBjMWE2Mjk2M2Y4ZDA2OWFiNDg2YWY5MzFiMDAzNjAwNGEifQ.eyJhenAiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDc5NjM5NjIxNDgwMzMzNDcwNTIiLCJhdF9oYXNoIjoiWXYwV1hLMTItT3Y1OW11RTBwVXpxdyIsIm5vbmNlIjoiNjY2NGIzZWI2NGQ1MWJiMTQyMDE1ODBhNmQyNjEzM2Q3M2QzYTk2NjVmZGM1YmM4MzViZWNiNjdlYmI0MWRhY18wY2M1M2U2ZjY1MzM5NzkzMGZkZTU2MzI3NWY0Mjg2OGZjMGY5OTc4IiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTA1MzI4Njk3LCJleHAiOjE1MDUzMzIyOTd9.piVQuDW0lK1SXSmUylLkdcHxLwE7IL5BpIboAv4i6O1qIe9KUcJFIE2YCUCQIAw1xnosr0o-KQ_m-9UDG401WUI4t8tO-IRhpufYvfwhNYexTclhD3b4TZQUATmhe0mxfZiYWWjnZhO-crG5kc1l9iDFO8Yu7UefpHIbjCVWtkC7UEOJXlzsKizTsU3FuseRMCOMD1PNEhS5iOILLce-O0VzdTtUSLvnUp15nEvHaXPLvLqbhGGCfabqfVEF1QuQ_APEp3WBhVgvhOy5aD0n0k7CS4yIz8NE-m9tzuMGkY8ujZAQDk_zV5nLx4ZdsdUMbBVMJxEabHVg0WdbKfBGPg';
    const AN_INVALID_TOKEN = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2ZGNiYTBjMWE2Mjk2M2Y4ZDA2OWFiNDg2YWY5MzFiMDAzNjAwNGEifQ.eyJhenAiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDc5NjM5NjIxNDgwMzMzNDcwNTIiLCJhdF9oYXNoIjoiWXYwV1hLMTItT3Y1OW11RTBwVXpxdyIsIm5vbmNlIjoiNjY2NGIzZWI2NGQ1MWJiMTQyMDE1ODBhNmQyNjEzM2Q3M2QzYTk2NjVmZGM1YmM4MzViZWNiNjdlYmI0MWRhY18wY2M1M2U2ZjY1MzM5NzkzMGZkZTU2MzI3NWY0Mjg2OGZjMGY5OTc4IiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTA1MzI4Njk3LCJleHAiOjE1MDUzMzIyOTd9';

    /**
     * @var IdToken|TestableIdToken
     */
    private $id_token;

    /**
     * @var MockObject|GenericOpenidProvider
     */
    private $provider;

    public function setUp(): void
    {
        $this->provider = $this->getMockBuilder(GenericOpenidProvider::class)
            ->setMethods(['getJwtVerificationKeys', 'validateNonce', 'getClientId', 'getOpenidConfiguration'])
            ->getMock();

        $this->provider->method('getJwtVerificationKeys')
            ->willReturn(self::VALID_JWT_KEYS);
    }

    public function test_NoIdTokenOption_New_ShouldThrow()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Required option not passed: "id_token"');

        $this->id_token = new TestableIdToken([], $this->provider);
    }

    public function test_InvalidIdTokenOption_New_ShouldThrow()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to parse the id_token!');

        $this->id_token = new IdToken(self::AN_INVALID_TOKEN, $this->provider);
    }

    public function test_InvalidNonce_validateIdToken_ShouldThrow()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');
        $this->provider->expects($this->once())
            ->method('validateNonce')
            ->willReturn(false);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The nonce is invalid!');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);
        $this->id_token->emptyNonce();
        $this->id_token->validate($this->provider);
    }

    public function test_InvalidAudience_validateIdToken_ShouldThrow()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');
        $this->provider->expects($this->once())
            ->method('validateNonce')
            ->willReturn(true);
        $this->provider->expects($this->once())
            ->method('getClientId')
            ->willReturn(self::INVALID_CLIENT_ID);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The audience is invalid!');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);
        $this->id_token->validate($this->provider);
    }

    public function test_InvalidIssuer_validateIdToken_ShouldThrow()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');
        $this->provider->expects($this->once())
            ->method('validateNonce')
            ->willReturn(true);
        $this->provider->expects($this->once())
            ->method('getClientId')
            ->willReturn(self::VALID_CLIENT_ID);

        $invalid_openid_config = self::OPENID_CONFIGURATION;
        $invalid_openid_config['issuer'] = '';
        $this->provider->expects($this->once())
            ->method('getOpenidConfiguration')
            ->willReturn($invalid_openid_config);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid token issuer!');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);
        $this->id_token->validate($this->provider);
    }

    public function test_ValidIdToken_getClaims_ShouldReturnParsedClaims()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);

        $expected = self::PARSED_CLAIMS;
        $actual = $this->id_token->getClaims();

        $this->assertEquals($expected, $actual);
    }

    public function test_ValidIdToken_getUserId_ShouldReturnUserId()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);

        $expected = self::USER_ID;
        $actual = $this->id_token->getUserId();

        $this->assertEquals($expected, $actual);
    }

    public function test_ValidIdToken_getIdToken_ShouldReturnIdToken()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);

        $expected = self::A_VALID_TOKEN;
        $actual = $this->id_token->getIdToken();

        $this->assertEquals($expected, $actual);
    }

    public function test_ValidIdToken_jsonSerialize_ShouldReturnParsedClaims()
    {
        $this->provider->expects($this->once())
            ->method('getJwtVerificationKeys');

        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);

        $expected = self::PARSED_CLAIMS;
        $actual = $this->id_token->jsonSerialize();

        $this->assertEquals($expected, $actual);
    }

    public function test_ValidIdToken___toString_ShouldReturnIdTokenKey()
    {
        $this->id_token = new TestableIdToken(self::A_VALID_TOKEN, $this->provider);

        $expected = self::A_VALID_TOKEN;
        $actual = (string)$this->id_token;

        $this->assertEquals($expected, $actual);
    }
}

class TestableIdToken extends IdToken
{

    public function parseIdToken($id_token, $keys)
    {
        return IdTokenTestCase::PARSED_CLAIMS;
    }

    public function validate(GenericOpenidProvider $provider)
    {
        parent::validateIdToken($provider);
    }

    protected function validateIdToken(GenericOpenidProvider $provider)
    {
    }

    public function emptyNonce()
    {
        $this->idTokenClaims['nonce'] = '';
    }
}
