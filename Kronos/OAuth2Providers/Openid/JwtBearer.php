<?php

namespace Kronos\OAuth2Providers\Openid;

use League\OAuth2\Client\Grant\AbstractGrant;

class JwtBearer extends AbstractGrant {
	protected function getName() {
		return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
	}

	protected function getRequiredRequestParameters() {
		return [
			'requested_token_use',
			'assertion'
		];
	}
}
