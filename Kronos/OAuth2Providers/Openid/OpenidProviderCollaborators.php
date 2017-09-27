<?php

namespace Kronos\OAuth2Providers\Openid;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Tool\RequestFactory;

class OpenidProviderCollaborators {

	/**
	 * @var GrantFactory
	 */
	protected $grantFactory;

	/**
	 * @var RequestFactory
	 */
	protected $requestFactory;

	/**
	 * @var HttpClientInterface
	 */
	protected $httpClient;


	public function __construct(GrantFactory $grantFactory = null, RequestFactory $requestFactory = null, HttpClient $httpClient = null) {
		$this->grantFactory = $grantFactory ?: new GrantFactory();
		$this->requestFactory = $requestFactory ?: new RequestFactory();
		$this->httpClient = $httpClient ?: new HttpClient();
	}

	/**
	 * @return GrantFactory
	 */
	public function getGrantFactory() {
		return $this->grantFactory;
	}

	/**
	 * @return RequestFactory
	 */
	public function getRequestFactory() {
		return $this->requestFactory;
	}

	/**
	 * @return HttpClientInterface
	 */
	public function getHttpClient() {
		return $this->httpClient;
	}
}