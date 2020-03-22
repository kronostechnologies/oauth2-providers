<?php

namespace Kronos\OAuth2Providers\Openid;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenParser;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenValidator;
use Kronos\OAuth2Providers\State\NonceServiceInterface;
use Kronos\OAuth2Providers\Openid\IdToken\IdTokenFactory;
use Kronos\OAuth2Providers\State\SessionBasedHashService;
use Kronos\OAuth2Providers\State\StateServiceInterface;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Tool\RequestFactory;

class OpenidProviderCollaborators
{

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
     * @var StateServiceInterface
     */
    protected $stateService;

    /**
     * @var NonceServiceInterface
     */
    protected $nonceService;


    /**
     * @var IdTokenFactory
     */
    protected $idTokenFactory;


    public function __construct(
        GrantFactory $grantFactory = null,
        RequestFactory $requestFactory = null,
        HttpClient $httpClient = null,
        StateServiceInterface $stateService = null,
        NonceServiceInterface $nonceService = null,
        IdTokenFactory $idTokenFactory = null
    ) {
        $this->grantFactory = $grantFactory ?: new GrantFactory();
        $this->requestFactory = $requestFactory ?: new RequestFactory();
        $this->httpClient = $httpClient ?: new HttpClient();
        $this->stateService = $stateService ?: new SessionBasedHashService();
        $this->nonceService = $nonceService ?: new SessionBasedHashService();
        $this->idTokenFactory = $idTokenFactory ?: new IdTokenFactory(new IdTokenParser(),
            new IdTokenValidator($this->nonceService));
    }

    /**
     * @return GrantFactory
     */
    public function getGrantFactory()
    {
        return $this->grantFactory;
    }

    /**
     * @return RequestFactory
     */
    public function getRequestFactory()
    {
        return $this->requestFactory;
    }

    /**
     * @return HttpClientInterface
     */
    public function getHttpClient()
    {
        return $this->httpClient;
    }

    /**
     * @return StateServiceInterface
     */
    public function getStateService()
    {
        return $this->stateService;
    }

    /**
     * @return NonceServiceInterface
     */
    public function getNonceService()
    {
        return $this->nonceService;
    }

    /**
     * @return IdTokenFactory
     */
    public function getIdTokenFactory()
    {
        return $this->idTokenFactory;
    }
}
