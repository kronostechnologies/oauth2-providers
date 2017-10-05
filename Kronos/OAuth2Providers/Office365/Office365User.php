<?php

namespace Kronos\OAuth2Providers\Office365;

use Kronos\OAuth2Providers\MicrosoftGraph\MicrosoftGraphUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;


class Office365User extends MicrosoftGraphUser implements ResourceOwnerInterface  {
}