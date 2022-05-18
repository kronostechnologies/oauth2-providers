<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use Kronos\OAuth2Providers\Openid\JwksResponseParser;
use Kronos\Tests\OAuth2Providers\Openid\Fixtures;
use PHPUnit\Framework\TestCase;

class IdTokenParserTest extends TestCase
{
    public function test_ValidStringWithMatchingKeys_parseIdToken_ShouldReturnClaims()
    {
        $keys = (new JwksResponseParser())->getVerificationKeys(Fixtures::JWKS_RESPONSE);
        $parser = new IdTokenParser();

        $claims = $parser->parseIdToken(Fixtures::ID_TOKEN, $keys);

        $this->assertEquals(Fixtures::ID_TOKEN_CLAIMS, $claims);
    }
}
