<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use PHPUnit\Framework\TestCase;

class IdTokenTest extends TestCase
{
    private const A_CLAIMS_ARRAY = [
        'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'sub' => '107963962148033347052',
        'iat' => 1505328697,
        'exp' => 1505332297
    ];

    private const A_CLAIMS_ARRAY_WITHOUT_SUB = [
        'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
        'iat' => 1505328697,
        'exp' => 1505332297
    ];

    private const A_NON_DEFAULT_USER_ID_KEY = 'aud';

    public function test_EmptyClaims_getClaims_ShouldReturnEmptyArray()
    {
        $idToken = new IdToken([], '');

        $expected = [];
        $actual = $idToken->getClaims();

        $this->assertEquals($expected, $actual);
    }

    public function test_NonEmptyClaims_getClaims_ShouldReturnClaims()
    {
        $idToken = new IdToken(self::A_CLAIMS_ARRAY, '');

        $expected = self::A_CLAIMS_ARRAY;
        $actual = $idToken->getClaims();

        $this->assertEquals($expected, $actual);
    }

    public function test_NonEmptyClaimsWithoutSub_getUserId_ShouldReturnNull()
    {
        $idToken = new IdToken(self::A_CLAIMS_ARRAY_WITHOUT_SUB, '');

        $expected = null;
        $actual = $idToken->getUserId();

        $this->assertEquals($expected, $actual);
    }

    public function test_NonEmptyClaimsWithNonDefaultUserId_getUserId_ShouldReturnUserId()
    {
        $idToken = new IdToken(self::A_CLAIMS_ARRAY, self::A_NON_DEFAULT_USER_ID_KEY);

        $expected = self::A_CLAIMS_ARRAY[self::A_NON_DEFAULT_USER_ID_KEY];
        $actual = $idToken->getUserId();

        $this->assertEquals($expected, $actual);
    }

    public function test_NonEmptyClaims_jsonSerialize_ShouldReturnClaims()
    {
        $idToken = new IdToken(self::A_CLAIMS_ARRAY, 'sub');

        $expected = self::A_CLAIMS_ARRAY;
        $actual = $idToken->jsonSerialize();

        $this->assertEquals($expected, $actual);
    }
}
