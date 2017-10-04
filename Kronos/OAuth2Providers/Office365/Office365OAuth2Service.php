<?php

namespace Kronos\OAuth2Providers\Office365;

use Kronos\OAuth2Providers\OAuthRefreshableInterface;
use Kronos\OAuth2Providers\OAuthServiceInterface;

class Office365OAuth2Service extends MicrosoftGraphOAuth2Service implements OAuthServiceInterface, OAuthRefreshableInterface {
}