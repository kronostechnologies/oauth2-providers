<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Firebase\JWT\Key;
use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenValidator;
use Kronos\Tests\OAuth2Providers\Openid\Fixtures;
use \PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class IdTokenFactoryTest extends TestCase
{


    const AN_ID_TOKEN_STRING = 'AN_ID_TOKEN_STRING';
    const A_KEYS_ARRAY = ['key1' => 'key1'];
    const A_CLIENT_ID = '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com';
    const AN_ISSUER = 'https://accounts.google.com';
    const A_NONCE = '6664b3eb64d51bb14201580a6d26133d73d3a9665fdc5bc835becb67ebb41dac_0cc53e6f653397930fde563275f42868fc0f9978';
    const A_USER_ID_KEY = 'sub';
    const A_USER_ID = '107963962148033347052';

    const A_PARSED_CLAIMS_ARRAY = [
        'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'sub' => '107963962148033347052',
        'nonce' => '6664b3eb64d51bb14201580a6d26133d73d3a9665fdc5bc835becb67ebb41dac_0cc53e6f653397930fde563275f42868fc0f9978',
        'iss' => 'https://accounts.google.com',
    ];
    const A_PARSER_EXCEPTION_MESSAGE = 'Unable to parse the id_token!';
    const A_VALIDATOR_EXCEPTION_MESSAGE = 'The audience is invalid!';

    /**
     * @var MockObject&IdTokenParser
     */
    private $parser;
    /**
     * @var MockObject&IdTokenValidator
     */
    private $validator;

    /**
     * @var array<string,Key>
     */
    private $keys = [];

    public function setUp(): void
    {
        $this->parser = $this->createMock(IdTokenParser::class);
        $this->validator = $this->createMock(IdTokenValidator::class);
        $key = $this->createMock(Key::class);
        $this->keys = [Fixtures::KEYID => $key];
    }

    public function test_WithArgument_New_ShouldSetServices()
    {
        $factory = new TestableIdTokenFactory($this->parser, $this->validator);

        $expected = $this->parser;
        $actual = $factory->getParser();
        $this->assertEquals($expected, $actual);

        $expected = $this->validator;
        $actual = $factory->getValidator();
        $this->assertEquals($expected, $actual);
    }

    public function test_WithoutArgument_New_ShouldCreateNewServices()
    {
        $factory = new TestableIdTokenFactory();

        $this->assertInstanceOf(IdTokenParser::class, $factory->getParser());
        $this->assertInstanceOf(IdTokenValidator::class, $factory->getValidator());
    }

    public function test_ValidArguments_createIdToken_ShouldReturnIdToken()
    {
        $idTokenString = self::AN_ID_TOKEN_STRING;
        $clientId = self:: A_CLIENT_ID;
        $issuer = self::AN_ISSUER;
        $userIdKey = self::A_USER_ID_KEY;

        $this->parser->expects($this->once())
            ->method('parseIdToken')
            ->with($idTokenString, $this->keys)
            ->willReturn(self::A_PARSED_CLAIMS_ARRAY);

        $this->validator->expects($this->once())
            ->method('validateIdTokenClaims')
            ->with(self::A_PARSED_CLAIMS_ARRAY, $clientId, $issuer);

        $factory = new TestableIdTokenFactory($this->parser, $this->validator);
        $idToken = $factory->createIdToken($idTokenString, $this->keys, $clientId, $issuer, $userIdKey);

        $this->assertInstanceOf(IdToken::class, $idToken);

        $expected = self::A_USER_ID;
        $actual = $idToken->getUserId();
        $this->assertEquals($expected, $actual);

        $expected = self::A_PARSED_CLAIMS_ARRAY;
        $actual = $idToken->getClaims();
        $this->assertEquals($expected, $actual);
    }

    public function test_ParseError_createIdToken_ShouldThrow()
    {
        $idTokenString = self::AN_ID_TOKEN_STRING;
        $clientId = self:: A_CLIENT_ID;
        $issuer = self::AN_ISSUER;
        $userIdKey = self::A_USER_ID_KEY;


        $exception = new RuntimeException(self::A_PARSER_EXCEPTION_MESSAGE);

        $this->parser->expects($this->once())
            ->method('parseIdToken')
            ->with($idTokenString, $this->keys)
            ->willThrowException($exception);

        $factory = new TestableIdTokenFactory($this->parser, $this->validator);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::A_PARSER_EXCEPTION_MESSAGE);

        $factory->createIdToken($idTokenString, $this->keys, $clientId, $issuer, $userIdKey);
    }

    public function test_ValidateError_createIdToken_ShouldThrow()
    {
        $idTokenString = self::AN_ID_TOKEN_STRING;
        $clientId = self:: A_CLIENT_ID;
        $issuer = self::AN_ISSUER;
        $userIdKey = self::A_USER_ID_KEY;

        $this->parser->expects($this->once())
            ->method('parseIdToken')
            ->with($idTokenString, $this->keys)
            ->willReturn(self::A_PARSED_CLAIMS_ARRAY);

        $exception = new RuntimeException(self::A_VALIDATOR_EXCEPTION_MESSAGE);

        $this->validator->expects($this->once())
            ->method('validateIdTokenClaims')
            ->with(self::A_PARSED_CLAIMS_ARRAY, $clientId, $issuer)
            ->willThrowException($exception);

        $factory = new TestableIdTokenFactory($this->parser, $this->validator);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(self::A_VALIDATOR_EXCEPTION_MESSAGE);

        $factory->createIdToken($idTokenString, $this->keys, $clientId, $issuer, $userIdKey);
    }
}

class TestableIdTokenFactory extends IdTokenFactory
{

    public function getParser()
    {
        return $this->idTokenParser;
    }

    public function getValidator()
    {
        return $this->idTokenValidator;
    }
}
