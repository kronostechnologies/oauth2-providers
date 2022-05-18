<?php

namespace Kronos\Tests\OAuth2Providers\Openid\IdToken;

use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use Kronos\Tests\OAuth2Providers\Openid\Fixtures;
use PHPUnit\Framework\TestCase;

class IdTokenParserTest extends TestCase
{
    public function test_ValidStringWithMatchingKeys_parseIdToken_ShouldReturnClaims()
    {
        $parser = new IdTokenParser();

        $claims = $parser->parseIdToken(Fixtures::ID_TOKEN, Fixtures::JWKS_KEY_STRINGS);

        $this->assertEquals(Fixtures::ID_TOKEN_CLAIMS, $claims);
    }
}
