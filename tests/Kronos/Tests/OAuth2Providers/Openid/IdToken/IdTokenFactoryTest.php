<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenValidator;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;

class IdTokenFactoryTest extends PHPUnit_Framework_TestCase {


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

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|IdTokenParser
	 */
	private $parser;
	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|IdTokenValidator
	 */
	private $validator;

	public function setUp() {
		$this->parser = $this->getMockBuilder(IdTokenParser::class)
			->disableOriginalConstructor()
			->getMock();
		$this->validator = $this->getMockBuilder(IdTokenValidator::class)
			->disableOriginalConstructor()
			->getMock();
	}

	public function test_WithArgument_New_ShouldSetServices(){
		$factory = new TestableIdTokenFactory($this->parser, $this->validator);

		$expected = $this->parser;
		$actual = $factory->getParser();
		$this->assertEquals($expected, $actual);

		$expected = $this->validator;
		$actual = $factory->getValidator();
		$this->assertEquals($expected, $actual);
	}

	public function test_WithoutArgument_New_ShouldCreateNewServices(){
		$factory = new TestableIdTokenFactory();

		$this->assertInstanceOf(IdTokenParser::class, $factory->getParser());
		$this->assertInstanceOf(IdTokenValidator::class, $factory->getValidator());
	}

	public function test_ValidArguments_createIdToken_ShouldReturnIdToken(){
		$idTokenString = self::AN_ID_TOKEN_STRING;
		$keys = self::A_KEYS_ARRAY;
		$clientId = self:: A_CLIENT_ID;
		$issuer = self::AN_ISSUER;
		$nonce = self::A_NONCE;
		$userIdKey = self::A_USER_ID_KEY;

		$this->parser->expects($this->once())
			->method('parseIdToken')
			->with($idTokenString, $keys)
			->willReturn(self::A_PARSED_CLAIMS_ARRAY);

		$this->validator->expects($this->once())
			->method('validateIdTokenClaims')
			->with(self::A_PARSED_CLAIMS_ARRAY, $clientId, $issuer, $nonce);

		$factory = new TestableIdTokenFactory($this->parser, $this->validator);
		$idToken = $factory->createIdToken($idTokenString, $keys, $clientId, $issuer, $nonce, $userIdKey);

		$this->assertInstanceOf(IdToken::class, $idToken);

		$expected = self::A_USER_ID;
		$actual = $idToken->getUserId();
		$this->assertEquals($expected, $actual);

		$expected = self::A_PARSED_CLAIMS_ARRAY;
		$actual = $idToken->getClaims();
		$this->assertEquals($expected, $actual);
	}
}

class TestableIdTokenFactory extends IdTokenFactory {

	public function getParser(){
		return $this->idTokenParser;
	}

	public function getValidator(){
		return $this->idTokenValidator;
	}
}