<?php

namespace Kronos\OAuth2Providers\Openid;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\SessionBasedHashService;
use League\OAuth2\Client\Grant\AbstractGrant;
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

	/**
	 * @var SessionBasedHashService
	 */
	protected $hashService;

	/**
	 * @var IdTokenFactory
	 */
	protected $idTokenFactory;


	public function __construct(GrantFactory $grantFactory = null, RequestFactory $requestFactory = null, HttpClient $httpClient = null, SessionBasedHashService $hashService = null, IdTokenFactory $idTokenFactory = null) {
		$this->grantFactory = $grantFactory ?: new GrantFactory();
		$this->requestFactory = $requestFactory ?: new RequestFactory();
		$this->httpClient = $httpClient ?: new HttpClient();
		$this->hashService = $hashService ?: new SessionBasedHashService();
		$this->idTokenFactory = $idTokenFactory ?: new IdTokenFactory();
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

	/**
	 * @return SessionBasedHashService
	 */
	public function getHashService() {
		return $this->hashService;
	}

	/**
	 * @return IdTokenFactory
	 */
	public function getIdTokenFactory() {
		return $this->idTokenFactory;
	}
}