<?php

namespace Kronos\OAuth2Providers\Office365;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use EightyOneSquare\OAuth2\Client\Provider\MicrosoftGraphUser;

class Office365User extends MicrosoftGraphUser implements ResourceOwnerInterface  {

}