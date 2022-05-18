<?php

namespace Kronos\Tests\OAuth2Providers\Openid;

use Kronos\OAuth2Providers\Openid\JwksResponseParser;
use PHPUnit\Framework\TestCase;

class JwksResponseParserTest extends TestCase
{
    private JwksResponseParser $parser;

    public function setUp(): void
    {
        parent::setUp();
        $this->parser = new JwksResponseParser();
    }

    public function test_getVerificationKeys_returnKeyStringArray(): void
    {
        $result = $this->parser->getVerificationKeys(Fixtures::JWKS_RESPONSE);

        self::assertCount(1, $result);
        self::assertArrayHasKey(Fixtures::KEYID, $result);
    }
}
