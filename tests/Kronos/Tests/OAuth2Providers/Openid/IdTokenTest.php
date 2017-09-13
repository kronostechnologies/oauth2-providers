<?php

use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken;

class IdTokenTest extends PHPUnit_Framework_TestCase {

	const VALID_OPTIONS = ['id_token' => 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2ZGNiYTBjMWE2Mjk2M2Y4ZDA2OWFiNDg2YWY5MzFiMDAzNjAwNGEifQ.eyJhenAiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDc5NjM5NjIxNDgwMzMzNDcwNTIiLCJhdF9oYXNoIjoiWXYwV1hLMTItT3Y1OW11RTBwVXpxdyIsIm5vbmNlIjoiNjY2NGIzZWI2NGQ1MWJiMTQyMDE1ODBhNmQyNjEzM2Q3M2QzYTk2NjVmZGM1YmM4MzViZWNiNjdlYmI0MWRhY18wY2M1M2U2ZjY1MzM5NzkzMGZkZTU2MzI3NWY0Mjg2OGZjMGY5OTc4IiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTA1MzI4Njk3LCJleHAiOjE1MDUzMzIyOTd9.piVQuDW0lK1SXSmUylLkdcHxLwE7IL5BpIboAv4i6O1qIe9KUcJFIE2YCUCQIAw1xnosr0o-KQ_m-9UDG401WUI4t8tO-IRhpufYvfwhNYexTclhD3b4TZQUATmhe0mxfZiYWWjnZhO-crG5kc1l9iDFO8Yu7UefpHIbjCVWtkC7UEOJXlzsKizTsU3FuseRMCOMD1PNEhS5iOILLce-O0VzdTtUSLvnUp15nEvHaXPLvLqbhGGCfabqfVEF1QuQ_APEp3WBhVgvhOy5aD0n0k7CS4yIz8NE-m9tzuMGkY8ujZAQDk_zV5nLx4ZdsdUMbBVMJxEabHVg0WdbKfBGPg'];
	const INVALID_OPTIONS = ['id_token' => 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2ZGNiYTBjMWE2Mjk2M2Y4ZDA2OWFiNDg2YWY5MzFiMDAzNjAwNGEifQ.eyJhenAiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxNjQ3ODUzMTA4NjgtbzFxa2luZWgxOWQyZmN2cXNmM3RxYWNsY3Q5bm0zOWQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDc5NjM5NjIxNDgwMzMzNDcwNTIiLCJhdF9oYXNoIjoiWXYwV1hLMTItT3Y1OW11RTBwVXpxdyIsIm5vbmNlIjoiNjY2NGIzZWI2NGQ1MWJiMTQyMDE1ODBhNmQyNjEzM2Q3M2QzYTk2NjVmZGM1YmM4MzViZWNiNjdlYmI0MWRhY18wY2M1M2U2ZjY1MzM5NzkzMGZkZTU2MzI3NWY0Mjg2OGZjMGY5OTc4IiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiaWF0IjoxNTA1MzI4Njk3LCJleHAiOjE1MDUzMzIyOTd9'];

	/**
	 * @var IdToken
	 */
	private $id_token;

	private $provider;

	public function setUp() {
		$this->provider = new MockGenericOpenidProvider();
	}

	public function test_NoIdTokenOption_New_ShouldThrow() {
		$this->expectException(InvalidArgumentException::class);
		$this->expectExceptionMessage('Required option not passed: "id_token"');

		$token = new IdToken([], $this->provider);
	}

	public function test_InvalidIdTokenOption_New_ShouldThrow() {
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage("Unable to parse the id_token!");

		$token = new IdToken(self::INVALID_OPTIONS, $this->provider);
	}

	public function test_InvalidKeys_New_ShouldThrow() {
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage("Unable to parse the id_token!");

		$token = new IdToken(self::VALID_OPTIONS, $this->provider);
	}
}

class MockGenericOpenidProvider extends GenericOpenidProvider {

	public function getJwtVerificationKeys() {
		return ['288c8449ce6038da2beca551dd5b7fe1a8a603a2' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlQ8I4NKbTgTCXSsDWTPP
l4W7DWkj201Se7G45NXe4l9dQ09WZ767FOcSfeVR+HQrCKU0MwA2CW78MGtWhSep
wgkjGSXcFg15X9Q8RVxbptN0zXku2TVubjlh+Ff714cmNxSqJwylnBXfdSYzGLYw
ZDdmnngGPC8/WNOrdTKHlHG5wH9wMRdzBNC1CD2lndZD16X6PMdIBwBp7/qxmRp0
VIVaBe7AHx4iOvY8t6ITjueU0JfAKAwptfqIUCpzcnKYLuvt/Yb4JI5f3XB3wLws
EXeVbAKdk+E8cHbPObQovAff4q3rbEoBEXT1HO1VhNYN6FuLiR3/ESycgpOkpjkg
8wIDAQAB
		-----END PUBLIC KEY-----',
			'06dcba0c1a62963f8d069ab486af931b0036004a' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZJ0vMEk1zqDvxd2Rq2C
zbRnR/BXS/QhCnVCVsMl4vJAPjeavccCkLxK/alM5uu+QFHwBtafdJJS1poATPWe
7Rmvo94TuUz0cHoSW38JfmhEqypZ+SbSNNA903dX2dxpZZOPLpbw34un6txSue8X
Qo+VHuSge5X0PYI03H3aOA0yKoc5RzeINmJbsys09vHIKHywGayn0CMO80L0iCNM
CHwGa3PiQLDO6k1Ob99ldBLUOvSw3ymJoIuvVftq+wDpkwZ1p/ouPCfPB7lA5uJT
srjpRv3Uj6+PVL4yIF8RrCO48Afw2LbaNluwTucFF5PHDB/hXvVqThIvKjP/t2zS
+QIDAQAB
-----END PUBLIC KEY-----',
			'303b2855a91438570ca72850491741e96bd99ef8' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxjHhLN2489+vNqJrOTWb
NS+f1H810owFC+bZii1eAZ3UfAnB92V9lPsU/x9IKSLCLrsGIMfVG9Zs+m+7g8xG
Q/tUrCnHZF0CWgGt14LV53caoSIh7jXSz18zsTMIF0U5Fn1y4gARAp2KHh9qnuK9
Nd5dnvZ9MC2vkknDkGjv8/9pKpo+SRjiFp+U+rprpcbwR/lRw2/Kk8IIZY7MLiDn
kfTxAnPOJz7KNezpUPElzO9efyd1E7vjbXrHvu2BybMdNfqSGu3Mmx23LzFL3pfC
sjTycgxQACSlAS3DVxeQWygbOyz27wYo1F1P7nsKk0p+Gjfk/izQhuOz4Z73MHdr
LQIDAQAB
-----END PUBLIC KEY-----'
		];
	}

	public function validateNonce($nonce) {
		return true;
	}

	public function getClientId(){
		return '164785310868-o1qkineh19d2fcvqsf3tqaclct9nm39d.apps.googleusercontent.com';
	}
}