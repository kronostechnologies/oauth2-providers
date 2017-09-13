<?php

use Kronos\OAuth2Providers\Openid\GenericOpenidProvider;
use Kronos\OAuth2Providers\Openid\IdToken;

class IdTokenTest extends PHPUnit_Framework_TestCase {

	const VALID_OPTIONS = ['id_token' => 'eyJhbGciOiJFUzI1NiIsImtpZCI6IjM0NjZkNTFmN2RkMGM3ODA1NjU2ODhjMTgzOTIxODE2YzQ1ODg5YWQifQ.eyJhdWQiOiJkajB5Sm1rOWJrMTVhM0ZYVjJ0NWNEbHRKbVE5V1Zkck9WbFZNWFJrYmtJMVRsUkJiV05IYnpsTlFTMHRKbk05WTI5dWMzVnRaWEp6WldOeVpYUW1lRDA0TUEtLSIsInN1YiI6IlVRSURXSk5XVk5RRDRHWFo1TkdNWlVTVFE0IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi55YWhvby5jb20iLCJleHAiOjE0NDQ2OTcwNDUsIm5vbmNlIjoiWWloc0Z3R0tndDNLSlVoNnRQczIiLCJpYXQiOjE0NDQ2OTM0NDV9.XiyNdHHHoYqarDZGkhln5sF_SQNNVvV67SZsFAk7yo8NreJjzVw7LmtkwpiUQe87-Km39PeIwf1W_PqEH9RqjA"'];
const INVALID_OPTIONS = ['id_token' => 'eyJhbGciOiJFUzI1NiIsImtpZCI6IjM0NjZkNTFmN2RkMGM3ODA1NjU2ODhjMTgzOTIxODE2YzQ1ODg5YWQifQ.eyJhdWQiOiJkajB5Sm1rOWJrMTVhM0ZYVjJ0NWNEbHRKbVE5V1Zkck9WbFZNWFJrYmtJMVRsUkJiV05IYnpsTlFTMHRKbk05WTI5dWMzVnRaWEp6WldOeVpYUW1lRDA0TUEtLSIsInN1YiI6IlVRSURXSk5XVk5RRDRHWFo1TkdNWlVTVFE0IiwiaXNzIjoiaHR0cHM6Ly9sb2dpbi55YWhvby5jb20iLCJleHAiOjE0NDQ2OTcwNDUsIm5vbmNlIjoiWWloc0Z3R0tndDNLSlVoNnRQczIiLCJpYXQiOjE0NDQ2OTM0NDV9'];

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

	public function test_InvalidKeys_New_ShouldThrow(){
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage("Unable to parse the id_token!");

		$token = new IdToken(self::VALID_OPTIONS, $this->provider);
	}
}

class MockGenericOpenidProvider extends GenericOpenidProvider {

	public function getJwtVerificationKeys() {
		return ['keys' =>
			[
				'kty' => 'RSA',
				'alg' => 'RS256',
				'use' => 'sig',
				'kid' => '288c8449ce6038da2beca551dd5b7fe1a8a603a2',
				'n' => 'lQ8I4NKbTgTCXSsDWTPPl4W7DWkj201Se7G45NXe4l9dQ09WZ767FOcSfeVR-HQrCKU0MwA2CW78MGtWhSepwgkjGSXcFg15X9Q8RVxbptN0zXku2TVubjlh-Ff714cmNxSqJwylnBXfdSYzGLYwZDdmnngGPC8_WNOrdTKHlHG5wH9wMRdzBNC1CD2lndZD16X6PMdIBwBp7_qxmRp0VIVaBe7AHx4iOvY8t6ITjueU0JfAKAwptfqIUCpzcnKYLuvt_Yb4JI5f3XB3wLwsEXeVbAKdk-E8cHbPObQovAff4q3rbEoBEXT1HO1VhNYN6FuLiR3_ESycgpOkpjkg8w',
				'e' => 'AQAB'
			],
			[
				'kty' => 'RSA',
				'alg' => 'RS256',
				'use' => 'sig',
				'kid' => '06dcba0c1a62963f8d069ab486af931b0036004a',
				'n' => '1ZJ0vMEk1zqDvxd2Rq2CzbRnR_BXS_QhCnVCVsMl4vJAPjeavccCkLxK_alM5uu-QFHwBtafdJJS1poATPWe7Rmvo94TuUz0cHoSW38JfmhEqypZ-SbSNNA903dX2dxpZZOPLpbw34un6txSue8XQo-VHuSge5X0PYI03H3aOA0yKoc5RzeINmJbsys09vHIKHywGayn0CMO80L0iCNMCHwGa3PiQLDO6k1Ob99ldBLUOvSw3ymJoIuvVftq-wDpkwZ1p_ouPCfPB7lA5uJTsrjpRv3Uj6-PVL4yIF8RrCO48Afw2LbaNluwTucFF5PHDB_hXvVqThIvKjP_t2zS-Q',
				'e' => 'AQAB'],
			[
				'kty' => 'RSA',
				'alg' => 'RS256',
				'use' => 'sig',
				'kid' => '303b2855a91438570ca72850491741e96bd99ef8',
				'n' => 'xjHhLN2489-vNqJrOTWbNS-f1H810owFC-bZii1eAZ3UfAnB92V9lPsU_x9IKSLCLrsGIMfVG9Zs-m-7g8xGQ_tUrCnHZF0CWgGt14LV53caoSIh7jXSz18zsTMIF0U5Fn1y4gARAp2KHh9qnuK9Nd5dnvZ9MC2vkknDkGjv8_9pKpo-SRjiFp-U-rprpcbwR_lRw2_Kk8IIZY7MLiDnkfTxAnPOJz7KNezpUPElzO9efyd1E7vjbXrHvu2BybMdNfqSGu3Mmx23LzFL3pfCsjTycgxQACSlAS3DVxeQWygbOyz27wYo1F1P7nsKk0p-Gjfk_izQhuOz4Z73MHdrLQ',
				'e' => 'AQAB']];
	}
}