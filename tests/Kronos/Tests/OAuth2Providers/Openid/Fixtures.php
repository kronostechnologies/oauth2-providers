<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

class Fixtures
{
    public const KEYID = "ZWiABzi6ox1dzVw2t-i58_Wa1iMy2WHa2NJGgNyn8iw";
    public const MODULUS = "z_uwpsAyAFho5tsXCBo8vo-zEbaSWunsSMvy9nExNH16gceFUQqx-SmqWWYRWnkhk7fdcrqpi6cp4P7fyPKXw7m9wpu1zlIE1GZS6qp2RiXX5vty0R77YthGhiOzGb1sEhqo7K6bkJMcUUJlkSuBzSynyiZg3i21R8t1mlkd2hKMxuaNESslL5VYETNU41jQw5T5HUOf-PZqU3VRCxT1Pn82jednSADISV3HLdvRcT9K2aH_68xHccicf59zSgiDhHWcZ96oqjzL_GuklmFcDb20Lscw8hAYoOryqUgY0i54a2SpvKaxqiEYgC2M8SBzjVlk9GN9n2rlg6se15_1dQ";
    public const EXPONENT = "AQAB";
    public const JWKS_RESPONSE = [
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
    public const PUBLIC_KEY_STRING = "-----BEGIN PUBLIC KEY-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz/uwpsAyAFho5tsXCBo8\r\nvo+zEbaSWunsSMvy9nExNH16gceFUQqx+SmqWWYRWnkhk7fdcrqpi6cp4P7fyPKX\r\nw7m9wpu1zlIE1GZS6qp2RiXX5vty0R77YthGhiOzGb1sEhqo7K6bkJMcUUJlkSuB\r\nzSynyiZg3i21R8t1mlkd2hKMxuaNESslL5VYETNU41jQw5T5HUOf+PZqU3VRCxT1\r\nPn82jednSADISV3HLdvRcT9K2aH/68xHccicf59zSgiDhHWcZ96oqjzL/GuklmFc\r\nDb20Lscw8hAYoOryqUgY0i54a2SpvKaxqiEYgC2M8SBzjVlk9GN9n2rlg6se15/1\r\ndQIDAQAB\r\n-----END PUBLIC KEY-----";
    public const ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlpXaUFCemk2b3gxZHpWdzJ0LWk1OF9XYTFpTXkyV0hhMk5KR2dOeW44aXcifQ.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20iLCJzdWIiOiJtYWlsdG86bWlrZUBleGFtcGxlLmNvbSIsIm5iZiI6MTY1Mjg5ODU4NSwiZXhwIjo0Mjk0OTY3Mjk1LCJpYXQiOjE1MDY1Mjk3NDQsImp0aSI6ImlkMTIzNDU2IiwidHlwIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9yZWdpc3RlciJ9.vwpXHi4IarHSiFKhYdTweb2ein97ApqqgHhYmlUEccvQZgWUxDdVOOZAkgWmuBL8cT4t6DSW6ibyaaCbTdf8p3xi-AjrExr4Xd8_MiUhHGhFAoUqMaJWZHvxDa7fpvGbIQM2jbZxKA9Rg8qbCQVmKsyxytPcxiFP1XrXT8rfnJjNho_5MFFRmUPCun0w7XfBtpt2lcETSscjcfJmBvHvPOuztqggRrcB8R9m1RKwE9vZG0r34O0crh0ABrAIXocixm-2ZYjYJMqUF-NaGYD2wkNqfLYSwJu7WPAPEJAxZeiM8JS0LP4ie48yjcsVs1tQtAS7cvZ8Ns9zRS-zN3rpIA";
    public const ID_TOKEN_CLAIMS = [
        "iss" => 'https://jwt-idp.example.com',
        "sub"=> "mailto:mike@example.com",
        "nbf"=> 1652898585,
        "iat"=> 1506529744,
        "exp" => 4294967295,
        "jti"=> "id123456",
        "typ"=> "https://example.com/register"
    ];
}
