<?php

namespace Kronos\OAuth2Providers\Exceptions;

use RuntimeException;

class ResourceOwnerUnsupportedException extends RuntimeException
{
    public function __construct(string $providerName = '')
    {
        parent::__construct("Provider $providerName does not support returning a Resource Owner.");
    }
}
