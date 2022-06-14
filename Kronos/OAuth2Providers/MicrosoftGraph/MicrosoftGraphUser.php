<?php

namespace Kronos\OAuth2Providers\MicrosoftGraph;

use EightyOneSquare\OAuth2\Client\Provider\MicrosoftGraphUser as BaseMicrosoftGraphUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class MicrosoftGraphUser extends BaseMicrosoftGraphUser implements ResourceOwnerInterface
{
}
