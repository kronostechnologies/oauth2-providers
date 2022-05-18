<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use Kronos\OAuth2Providers\Openid\JwksResponseParser;
use PHPUnit\Framework\TestCase;

class JwksResponseParserTest extends TestCase
{
    private JwksResponseParser $parser;

    private const KEYID = "ZWiABzi6ox1dzVw2t-i58_Wa1iMy2WHa2NJGgNyn8iw";
    private const MODULUS = "z_uwpsAyAFho5tsXCBo8vo-zEbaSWunsSMvy9nExNH16gceFUQqx-SmqWWYRWnkhk7fdcrqpi6cp4P7fyPKXw7m9wpu1zlIE1GZS6qp2RiXX5vty0R77YthGhiOzGb1sEhqo7K6bkJMcUUJlkSuBzSynyiZg3i21R8t1mlkd2hKMxuaNESslL5VYETNU41jQw5T5HUOf-PZqU3VRCxT1Pn82jednSADISV3HLdvRcT9K2aH_68xHccicf59zSgiDhHWcZ96oqjzL_GuklmFcDb20Lscw8hAYoOryqUgY0i54a2SpvKaxqiEYgC2M8SBzjVlk9GN9n2rlg6se15_1dQ";
    private const EXPONENT = "AQAB";
    private const JWKS_RESPONSE = [
        "keys" => [
            [
                "e" => self::EXPONENT,
                "n" => self::MODULUS,
                "kty" => "RSA",
                "kid" => self::KEYID,
                "use" => "sig",
                "x5c" => [
                    "MIIDIDCCAggCCQC77fWn88VEdjANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJDQTEPMA0GA1UECBMGUXVlYmVjMQ8wDQYDVQQHEwZRdWViZWMxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xNzEwMDUxODE5MjNaFw0xNzExMDQxODE5MjNaMFIxCzAJBgNVBAYTAkNBMQ8wDQYDVQQIEwZRdWViZWMxDzANBgNVBAcTBlF1ZWJlYzEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/uwpsAyAFho5tsXCBo8vo+zEbaSWunsSMvy9nExNH16gceFUQqx+SmqWWYRWnkhk7fdcrqpi6cp4P7fyPKXw7m9wpu1zlIE1GZS6qp2RiXX5vty0R77YthGhiOzGb1sEhqo7K6bkJMcUUJlkSuBzSynyiZg3i21R8t1mlkd2hKMxuaNESslL5VYETNU41jQw5T5HUOf+PZqU3VRCxT1Pn82jednSADISV3HLdvRcT9K2aH/68xHccicf59zSgiDhHWcZ96oqjzL/GuklmFcDb20Lscw8hAYoOryqUgY0i54a2SpvKaxqiEYgC2M8SBzjVlk9GN9n2rlg6se15/1dQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQBAyaGkbw5eRGGHzv7J0sGpEqfIw/KNNk5284jT6/NOjb3rijPud0MJ4H36d7qDp8raaDck3XJ7sRifuohLMgaPwORac63iJIQuDTyWCZnpIL7QPK3UETrlHiHtAsWVeBSXDLxJTC/tcIVbRaYE09Wm2HmlIFMT8ww9B/5j28hKpNb9wbb1zMYaN9oPUvNz2xn5tIJspcOSHax9UKBOzCfnNhr4aulf2yBp3PnQ70aYA0wNoA/QXYqSslZlKIxTikoIioVAY9oPfY1UFan4VWe/KjGzrEoi0cXH02Owyeukr6ojofdaMfQotyWDogLdUc0sP52OLRKSCL8NUePpY50c"
                ],
                "x5t" => "16yEspZknwf7q4geggMUX1KSYQc",
                "x5t#S256" => "qPR7XOuk_6mO6dKHYwI_njhEZFNbLira7NAWlD8Dyn4"
            ]
        ]

    ];
    private const PUBLIC_KEY_STRING = "-----BEGIN PUBLIC KEY-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/uwpsAyAFho5tsXCBo8\r\nvo+zEbaSWunsSMvy9nExNH16gceFUQqx+SmqWWYRWnkhk7fdcrqpi6cp4P7fyPKX\r\nw7m9wpu1zlIE1GZS6qp2RiXX5vty0R77YthGhiOzGb1sEhqo7K6bkJMcUUJlkSuB\r\nzSynyiZg3i21R8t1mlkd2hKMxuaNESslL5VYETNU41jQw5T5HUOf+PZqU3VRCxT1\r\nPn82jednSADISV3HLdvRcT9K2aH/68xHccicf59zSgiDhHWcZ96oqjzL/GuklmFc\r\nDb20Lscw8hAYoOryqUgY0i54a2SpvKaxqiEYgC2M8SBzjVlk9GN9n2rlg6se15/1\r\ndQIDAQAB\r\n-----END PUBLIC KEY-----";

    public function setUp(): void
    {
        parent::setUp();
        $this->parser = new JwksResponseParser();
    }

    public function test_getVerificationKeys_returnKeyStringArray(): void
    {
        $result = $this->parser->getVerificationKeys(self::JWKS_RESPONSE);

        self::assertEquals([
            self::KEYID => self::PUBLIC_KEY_STRING
        ], $result);
    }
}
