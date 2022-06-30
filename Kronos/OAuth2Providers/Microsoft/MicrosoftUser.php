<?php

namespace Kronos\OAuth2Providers\Microsoft;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use TheNetworg\OAuth2\Client\Provider\AzureResourceOwner;

class MicrosoftUser extends AzureResourceOwner implements ResourceOwnerInterface
{
    public function getPrincipalName(): ?string
    {
        return $this->getUpn();
    }

    public function getEmail(): ?string
    {
        return $this->claim('email');
    }

    public function getDisplayName(): ?string
    {
        return $this->claim('name');
    }
}
