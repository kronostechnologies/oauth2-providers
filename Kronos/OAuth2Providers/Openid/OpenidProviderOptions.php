<?php

namespace Kronos\OAuth2Providers\Openid;

class OpenidProviderOptions {

	protected $clientId;

	protected $clientSecret;

	protected $redirectUri;

	protected $openidConfigurationUrl;

	public function __construct($options) {
		$this->clientId = $options['clientId'];
		$this->clientSecret = $options['clientSecret'];
		$this->redirectUri = $options['redirectUri'];
		$this->openidConfigurationUrl = $options['openidConfigurationUrl'];
	}

	/**
	 * @return mixed
	 */
	public function getClientId() {
		return $this->clientId;
	}

	/**
	 * @return mixed
	 */
	public function getClientSecret() {
		return $this->clientSecret;
	}

	/**
	 * @return mixed
	 */
	public function getRedirectUri() {
		return $this->redirectUri;
	}

	/**
	 * @return mixed
	 */
	public function getOpenidConfigurationUrl() {
		return $this->openidConfigurationUrl;
	}
}