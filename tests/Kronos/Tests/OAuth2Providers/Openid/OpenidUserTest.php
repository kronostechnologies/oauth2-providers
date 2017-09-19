<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use Kronos\OAuth2Providers\Openid\IdToken;
use Kronos\OAuth2Providers\Openid\OpenidUser;
use PHPUnit_Framework_MockObject_MockObject;
use PHPUnit_Framework_TestCase;

class OpenidUserTest extends PHPUnit_Framework_TestCase {

	const A_USER_ID = 'AuSeRiD01234';
	const A_CLAIMS_ARRAY = ['aud' => 'dj0yJmk9bk15a3FXV2t5cDltJmQ9WVdrOVlVMXRkbkI1TlRBbWNHbzlNQS0tJnM9Y29uc3VtZXJzZWNyZXQmeD04MA--',
		'sub' => 'UQIDWJNWVNQD4GXZ5NGMZUSTQ4',
		'iss' => 'https://login.example.com',
		'exp' => 1444697045,
		'nonce' => 'YihsFwGKgt3KJUh6tPs2',
		'iat' => 1444693445];

	/**
	 * @var PHPUnit_Framework_MockObject_MockObject|IdToken
	 */
	private $id_token;

	/**
	 * @var OpenidUser
	 */
	private $openidUser;

	public function setUp() {
		$this->id_token = $this->getMockBuilder(IdToken::class)
			->disableOriginalConstructor()
			->setMethods(['parseIdToken', 'validateIdToken', 'getUserId', 'getClaims'])
			->getMock();

		$this->openidUser = new OpenidUser($this->id_token);
	}

	public function test_Id_getId_ShouldReturnId() {
		$this->id_token->expects($this->once())
			->method('getUserId')
			->willReturn(self::A_USER_ID);

		$expected = self::A_USER_ID;
		$actual = $this->openidUser->getId();

		$this->assertEquals($expected, $actual);
	}

	public function test_Id_toArray_ShouldReturnClaimsArray() {
		$this->id_token->expects($this->once())
			->method('getClaims')
			->willReturn(self::A_CLAIMS_ARRAY);

		$expected = self::A_CLAIMS_ARRAY;
		$actual = $this->openidUser->toArray();

		$this->assertEquals($expected, $actual);
	}
}