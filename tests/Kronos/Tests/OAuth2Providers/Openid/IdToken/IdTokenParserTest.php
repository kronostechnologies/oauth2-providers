<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use PHPUnit\Framework\TestCase;

class IdTokenParserTest extends TestCase {

	const A_VALID_TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MzUwMjgyODgwMCwiZXhwIjo0MTAyMzU4NDAwLCJpYXQiOjE1MDY1Mjk3NDQsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.xZ90KU2HTm1Ok-14f64I1OGuc7RIn5kzkzVsFVsXPchoHA4-oj8TWWszvkzmxhe40JcVRboRiaCSszGp-kDdVt85bVR3IBGWNAdP9Lt_L9k9WLranLjpN-0g7_F-Zx40e6vYUTV5d_Z-t2NuagFSomWa1NgvAiQSxFbVZ2FkeD0YKXW0CyViLWFHlab0m3cmYjE1T_wxNRDpZh0_L7I6HrwaGo7VYadSwteodCrsSLQpiPly0m27SJdlIdhF7vsYzf-xZisVW9sBCJuicYgZHxgk3x4oWEy5hYlzCy0ucdRZbIrRUYycgcJJPAhXe0LZbG6uAAsByqm-meZ4RJvCew';

	const A_PARSED_CLAIMS_ARRAY = [
		'azp' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com',
		'aud' => '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com'
	];

	const A_KEYS_ARRAY = [
		'288c8449ce6038da2beca551dd5b7fe1a8a603a2' => "-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----",
		'06dcba0c1a62963f8d069ab486af931b0036004a' => "-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----",
		'303b2855a91438570ca72850491741e96bd99ef8' => "-----BEGIN PUBLIC KEY-----
-----END PUBLIC KEY-----"
	];

	public function test_ValidStringWithMatchingKeys_parseIdToken_ShouldReturnClaims(){
		$parser = new TestableIdTokenParser();

		$expected = self::A_PARSED_CLAIMS_ARRAY;
		$actual = $parser->parseIdToken(self::A_VALID_TOKEN, self::A_KEYS_ARRAY);

		$this->assertEquals($expected, $actual);
	}
}

class TestableIdTokenParser extends IdTokenParser {

	protected function decodeJWT($idTokenString, $keys) {
		return IdTokenParserTest::A_PARSED_CLAIMS_ARRAY;
	}
}
