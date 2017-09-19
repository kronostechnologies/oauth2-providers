<?php

namespace Kronos\OAuth2Providers\Openid;

use Firebase\JWT\JWT;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\ClientInterface as HttpClientInterface;
use GuzzleHttp\Exception\BadResponseException;
use Kronos\OAuth2Providers\OpenidServiceInterface;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Grant\GrantFactory;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use League\OAuth2\Client\Tool\RequestFactory;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use UnexpectedValueException;

class GenericOpenidProvider implements OpenidServiceInterface {

	use ArrayAccessorTrait;
	use QueryBuilderTrait;

	/**
	 * @var string Key used in a token response to identify the resource owner.
	 */
	const ID_TOKEN_RESOURCE_OWNER_ID = 'sub';

	/**
	 * @var string HTTP method used to fetch access tokens.
	 */
	const METHOD_GET = 'GET';

	/**
	 * @var string HTTP method used to fetch access tokens.
	 */
	const METHOD_POST = 'POST';

	/**
	 * @var string
	 */
	protected $clientId;

	/**
	 * @var string
	 */
	protected $clientSecret;

	/**
	 * @var string
	 */
	protected $redirectUri;

	/**
	 * @var string
	 */
	protected $openidConfigurationUrl;

	/**
	 * @var array
	 */
	protected $openidConfiguration;

	/**
	 * @var string
	 */
	protected $state;

	/**
	 * @var string
	 */
	protected $nonce;

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
	 * Constructs an Openid Connect service provider.
	 *
	 * @param array $options An array of options to set on this provider.
	 *     Options include `clientId`, `clientSecret`, `redirectUri`, and `openidConfigurationUrl`.
	 *     Individual providers may introduce more options, as needed.
	 * @param array $collaborators An array of collaborators that may be used to
	 *     override this provider's default behavior. Collaborators include
	 *     `grantFactory`, `requestFactory`, and `httpClient`.
	 *     Individual providers may introduce more collaborators, as needed.
	 */
	public function __construct(array $options = [], array $collaborators = []) {
		foreach($options as $option => $value) {
			if(property_exists($this, $option)) {
				$this->{$option} = $value;
			}
		}

		if(empty($collaborators['grantFactory'])) {
			$collaborators['grantFactory'] = new GrantFactory();
		}
		$this->setGrantFactory($collaborators['grantFactory']);
		$this->grantFactory->setGrant('jwt_bearer', new JwtBearer);

		if(empty($collaborators['requestFactory'])) {
			$collaborators['requestFactory'] = new RequestFactory();
		}
		$this->setRequestFactory($collaborators['requestFactory']);

		if(empty($collaborators['httpClient'])) {
			$client_options = $this->getAllowedClientOptions($options);

			$collaborators['httpClient'] = new HttpClient(
				array_intersect_key($options, array_flip($client_options))
			);
		}
		$this->setHttpClient($collaborators['httpClient']);

		if(empty($this->openidConfiguration) && !empty($this->openidConfigurationUrl)) {
			$this->setOpenidConfiguration();
		}
	}

	/**
	 * Returns the client id
	 *
	 * @return string
	 */
	public function getClientId() {
		return $this->clientId;
	}

	/**
	 * Returns the list of options that can be passed to the HttpClient
	 *
	 * @param array $options An array of options to set on this provider.
	 *     Options include `clientId`, `clientSecret`, `redirectUri`, and `openidConfigurationUrl`.
	 *     Individual providers may introduce more options, as needed.
	 * @return array The options to pass to the HttpClient constructor
	 */
	protected function getAllowedClientOptions(array $options) {
		$client_options = ['timeout', 'proxy'];

		// Only allow turning off ssl verification if it's for a proxy
		if(!empty($options['proxy'])) {
			$client_options[] = 'verify';
		}

		return $client_options;
	}

	/**
	 * Sets the grant factory instance.
	 *
	 * @param  GrantFactory $factory
	 * @return self
	 */
	public function setGrantFactory(GrantFactory $factory) {
		$this->grantFactory = $factory;

		return $this;
	}

	/**
	 * Returns the current grant factory instance.
	 *
	 * @return GrantFactory
	 */
	public function getGrantFactory() {
		return $this->grantFactory;
	}

	/**
	 * Sets the request factory instance.
	 *
	 * @param  RequestFactory $factory
	 * @return self
	 */
	public function setRequestFactory(RequestFactory $factory) {
		$this->requestFactory = $factory;

		return $this;
	}

	/**
	 * Returns the request factory instance.
	 *
	 * @return RequestFactory
	 */
	public function getRequestFactory() {
		return $this->requestFactory;
	}

	/**
	 * Sets the HTTP client instance.
	 *
	 * @param  HttpClientInterface $client
	 * @return self
	 */
	public function setHttpClient(HttpClientInterface $client) {
		$this->httpClient = $client;

		return $this;
	}

	/**
	 * Returns the HTTP client instance.
	 *
	 * @return HttpClientInterface
	 */
	public function getHttpClient() {
		return $this->httpClient;
	}

	/**
	 * Returns the base URL for authorizing a client.
	 *
	 * Eg. https://oauth.service.com/authorize
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl() {
		$baseAuthUrl = '';
		if(!empty($this->openidConfiguration['authorization_endpoint'])){
			$baseAuthUrl = $this->openidConfiguration['authorization_endpoint'];
		}

		return $baseAuthUrl;
	}

	/**
	 * Returns the base URL for requesting an access token.
	 *
	 * Eg. https://oauth.service.com/token
	 *
	 * @return string
	 */
	public function getBaseIdTokenUrl() {
		$baseTokenUrl = '';
		if(!empty($this->openidConfiguration['token_endpoint'])){
			$baseTokenUrl = $this->openidConfiguration['token_endpoint'];
		}

		return $baseTokenUrl;
	}

	/**
	 * Returns the default scopes used by this provider.
	 *
	 * This should only be the scopes that are required to request the id_token, eg. 'openid',
	 * rather than all the available scopes.
	 *
	 * @return array
	 */
	protected function getDefaultScopes() {
		return ['openid'];
	}

	/**
	 * Returns the string that should be used to separate scopes when building
	 * the URL for requesting an access token.
	 *
	 * @return string Scope separator, defaults to ','
	 */
	protected function getScopeSeparator() {
		return ',';
	}

	/**
	 * Returns authorization parameters based on provided options.
	 *
	 * @param  array $options
	 * @return array Authorization parameters
	 */
	protected function getAuthorizationParameters(array $options) {
		if(empty($options['state'])) {
			$options['state'] = $this->getSessionState();
		}

		if(empty($options['nonce'])) {
			$options['nonce'] = $this->createNonce();
		}

		if(empty($options['scope'])) {
			$options['scope'] = $this->getDefaultScopes();
		}

		$options += [
			'response_type' => 'code',
			'approval_prompt' => 'auto'
		];

		if(is_array($options['scope'])) {
			$separator = $this->getScopeSeparator();
			$options['scope'] = implode($separator, $options['scope']);
		}

		// Store the state as it may need to be accessed later on.
		$this->state = $options['state'];

		// Business code layer might set a different redirect_uri parameter
		// depending on the context, leave it as-is
		if(!isset($options['redirect_uri'])) {
			$options['redirect_uri'] = $this->redirectUri;
		}

		$options['client_id'] = $this->clientId;

		return $options;
	}

	/**
	 * Builds the authorization URL's query string.
	 *
	 * @param  array $params Query parameters
	 * @return string Query string
	 */
	protected function getAuthorizationQuery(array $params) {
		return $this->buildQueryString($params);
	}

	/**
	 * Builds the authorization URL.
	 *
	 * @param  array $options
	 * @return string Authorization URL
	 */
	public function getAuthorizationUrl(array $options = []) {
		$base = $this->getBaseAuthorizationUrl();
		$params = $this->getAuthorizationParameters($options);
		$query = $this->getAuthorizationQuery($params);

		return $this->appendQuery($base, $query);
	}

	/**
	 * Appends a query string to a URL.
	 *
	 * @param  string $url The URL to append the query to
	 * @param  string $query The HTTP query string
	 * @return string The resulting URL
	 */
	protected function appendQuery($url, $query) {
		$query = trim($query, '?&');

		if($query) {
			$glue = strstr($url, '?') === false ? '?' : '&';
			return $url . $glue . $query;
		}

		return $url;
	}

	/**
	 * Returns the method to use when requesting an id token.
	 *
	 * @return string HTTP method
	 */
	protected function getIdTokenMethod() {
		return self::METHOD_POST;
	}

	/**
	 * Returns the key used in the id token response to identify the resource owner.
	 *
	 * @return string Resource owner identifier key
	 */
	protected function getIdTokenResourceOwnerId() {
		return static::ID_TOKEN_RESOURCE_OWNER_ID;
	}

	/**
	 * Builds the id token URL's query string.
	 *
	 * @param  array $params Query parameters
	 * @return string Query string
	 */
	protected function getIdTokenQuery(array $params) {
		return $this->buildQueryString($params);
	}

	/**
	 * Checks that a provided grant is valid, or attempts to produce one if the
	 * provided grant is a string.
	 *
	 * @param  AbstractGrant|string $grant
	 * @return AbstractGrant
	 */
	protected function verifyGrant($grant) {
		if(is_string($grant)) {
			return $this->grantFactory->getGrant($grant);
		}

		$this->grantFactory->checkGrant($grant);
		return $grant;
	}

	/**
	 * Returns the full URL to use when requesting an id token.
	 *
	 * @param array $params Query parameters
	 * @return string
	 */
	protected function getIdTokenUrl(array $params) {
		$url = $this->getBaseIdTokenUrl();

		if($this->getIdTokenMethod() === self::METHOD_GET) {
			$query = $this->getIdTokenQuery($params);
			return $this->appendQuery($url, $query);
		}

		return $url;
	}

	/**
	 * Returns the request body for requesting an id token.
	 *
	 * @param  array $params
	 * @return string
	 */
	protected function getIdTokenBody(array $params) {
		return $this->buildQueryString($params);
	}

	/**
	 * Builds request options used for requesting an id token.
	 *
	 * @param  array $params
	 * @return array
	 */
	protected function getIdTokenOptions(array $params) {
		$options = ['headers' => ['content-type' => 'application/x-www-form-urlencoded']];

		if($this->getIdTokenMethod() === self::METHOD_POST) {
			$options['body'] = $this->getIdTokenBody($params);
		}

		return $options;
	}

	/**
	 * Returns a prepared request for requesting an id token.
	 *
	 * @param array $params Query string parameters
	 * @return RequestInterface
	 */
	protected function getIdTokenRequest(array $params) {
		$method = $this->getIdTokenMethod();
		$url = $this->getIdTokenUrl($params);
		$options = $this->getIdTokenOptions($params);

		return $this->getRequest($method, $url, $options);
	}

	/**
	 * Requests and creates an id token.
	 *
	 * @param $grant
	 * @param array $options
	 * @return IdToken
	 */
	public function getIdToken($grant, array $options = []) {
		$prepared = $this->getIdTokenPreparedResponse($grant, $options);

		return $this->createIdToken($prepared, $this);
	}

	/**
	 * Requests an id token and returns the prepared response.
	 *
	 * @param $grant
	 * @param array $options
	 * @return array
	 */
	public function getIdTokenPreparedResponse($grant, array $options = []) {
		$grant = $this->verifyGrant($grant);

		$params = [
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'redirect_uri' => $this->redirectUri
		];

		$params = $grant->prepareRequestParameters($params, $options);
		$request = $this->getIdTokenRequest($params);
		$response = $this->getParsedResponse($request);
		$prepared = $this->prepareIdTokenResponse($response);

		return $prepared;
	}

	/**
	 * Requests an id token using an 'authorization_code' grant.
	 *
	 * @param string $authorization_code
	 * @return IdToken
	 */
	public function getIdTokenByAuthorizationCode($authorization_code) {
		return $this->getIdToken('authorization_code', [
			'code' => $authorization_code
		]);
	}

	/**
	 * Returns a PSR-7 request instance that is not authenticated.
	 *
	 * @param  string $method
	 * @param  string $url
	 * @param  array $options
	 * @return RequestInterface
	 */
	public function getRequest($method, $url, array $options = []) {
		return $this->createRequest($method, $url, null, $options);
	}

	/**
	 * Returns an authenticated PSR-7 request instance.
	 *
	 * @param  string $method
	 * @param  string $url
	 * @param  IdToken|string $token
	 * @param  array $options Any of "headers", "body", and "protocolVersion".
	 * @return RequestInterface
	 */
	public function getAuthenticatedRequest($method, $url, $token, array $options = []) {
		return $this->createRequest($method, $url, $token, $options);
	}

	/**
	 * Creates a PSR-7 request instance.
	 *
	 * @param  string $method
	 * @param  string $url
	 * @param  IdToken|string|null $token
	 * @param  array $options
	 * @return RequestInterface
	 */
	protected function createRequest($method, $url, $token, array $options) {
		$defaults = [
			'headers' => $this->getHeaders($token),
		];

		$options = array_merge_recursive($defaults, $options);
		$factory = $this->getRequestFactory();

		return $factory->getRequestWithOptions($method, $url, $options);
	}

	/**
	 * Sends a request instance and returns a response instance.
	 *
	 * WARNING: This method does not attempt to catch exceptions caused by HTTP
	 * errors! It is recommended to wrap this method in a try/catch block.
	 *
	 * @param  RequestInterface $request
	 * @return ResponseInterface
	 */
	public function getResponse(RequestInterface $request) {
		return $this->getHttpClient()->send($request);
	}

	/**
	 * Sends a request and returns the parsed response.
	 *
	 * @param  RequestInterface $request
	 * @return mixed
	 */
	public function getParsedResponse(RequestInterface $request) {
		try {
			$response = $this->getResponse($request);
		}
		catch(BadResponseException $e) {
			$response = $e->getResponse();
		}

		$parsed = $this->parseResponse($response);

		$this->checkResponse($response, $parsed);

		return $parsed;
	}

	/**
	 * Attempts to parse a JSON response.
	 *
	 * @param  string $content JSON content from response body
	 * @return array Parsed JSON data
	 * @throws UnexpectedValueException if the content could not be parsed
	 */
	protected function parseJson($content) {
		$content = json_decode($content, true);

		if(json_last_error() !== JSON_ERROR_NONE) {
			throw new UnexpectedValueException(sprintf(
				"Failed to parse JSON response: %s",
				json_last_error_msg()
			));
		}

		return $content;
	}

	/**
	 * Returns the content type header of a response.
	 *
	 * @param  ResponseInterface $response
	 * @return string Semi-colon separated join of content-type headers.
	 */
	protected function getContentType(ResponseInterface $response) {
		return join(';', (array)$response->getHeader('content-type'));
	}

	/**
	 * Parses the response according to its content-type header.
	 *
	 * @throws UnexpectedValueException
	 * @param  ResponseInterface $response
	 * @return array|string
	 */
	protected function parseResponse(ResponseInterface $response) {
		$content = (string)$response->getBody();
		$type = $this->getContentType($response);

		if(strpos($type, 'urlencoded') !== false) {
			parse_str($content, $parsed);
			return $parsed;
		}

		// Attempt to parse the string as JSON regardless of content type,
		// since some providers use non-standard content types. Only throw an
		// exception if the JSON could not be parsed when it was expected to.
		try {
			return $this->parseJson($content);
		}
		catch(UnexpectedValueException $e) {
			if(strpos($type, 'json') !== false) {
				throw $e;
			}

			if($response->getStatusCode() == 500) {
				throw new UnexpectedValueException(
					'An OpenId server error was encountered that did not contain a JSON body',
					0,
					$e
				);
			}

			return $content;
		}
	}

	/**
	 * Checks a provider response for errors.
	 *
	 * @throws IdentityProviderException
	 * @param  ResponseInterface $response
	 * @param  array|string $data Parsed response data
	 * @return void
	 */
	protected function checkResponse(ResponseInterface $response, $data) {
		if(isset($data['odata.error']) || isset($data['error'])) {
			if(isset($data['odata.error']['message']['value'])) {
				$message = $data['odata.error']['message']['value'];
			}
			elseif(isset($data['error']['message'])) {
				$message = $data['error']['message'];
			}
			else {
				$message = $response->getReasonPhrase();
			}

			throw new IdentityProviderException(
				$message,
				$response->getStatusCode(),
				$response
			);
		}
	}

	/**
	 * Prepares a parsed id token response for a grant.
	 *
	 * Custom mapping of expiration, etc should be done here. Always call the
	 * parent method when overloading this method.
	 *
	 * @param  mixed $result
	 * @return array
	 */
	protected function prepareIdTokenResponse(array $result) {
		if($this->getIdTokenResourceOwnerId() !== null) {
			$result['resource_owner_id'] = $this->getValueByKey(
				$result,
				$this->getIdTokenResourceOwnerId()
			);
		}
		return $result;
	}

	/**
	 * Creates an id token from a response.
	 *
	 * The provider that was used to fetch the response can be used to provide
	 * additional context.
	 *
	 * @param  array $response
	 * @param GenericOpenidProvider $provider
	 * @return IdToken
	 */
	protected function createIdToken(array $response, GenericOpenidProvider $provider) {
		return new IdToken($response, $provider);
	}

	/**
	 * Generates a resource owner object from an id token.
	 *
	 * @param  IdToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner(IdToken $token) {
		return new OpenidUser($token);
	}

	/**
	 * Creates and returns the resource owner of given id token.
	 *
	 * @param  IdToken $token
	 * @return ResourceOwnerInterface
	 */
	public function getResourceOwner(IdToken $token) {
		return $this->createResourceOwner($token);
	}

	/**
	 * Returns the default headers used by this provider.
	 *
	 * Typically this is used to set 'Accept' or 'Content-Type' headers.
	 *
	 * @return array
	 */
	protected function getDefaultHeaders() {
		return [];
	}

	/**
	 * Returns authorization headers for the 'bearer' grant.
	 *
	 * @param  mixed|null $token Either a string or an access token instance
	 * @return array
	 */
	protected function getAuthorizationHeaders($token = null) {
		return ['Authorization' => 'Bearer ' . $token];
	}

	/**
	 * Returns all headers used by this provider for a request.
	 *
	 * The request will be authenticated if an id token is provided.
	 *
	 * @param  mixed|null $token object or string
	 * @return array
	 */
	public function getHeaders($token = null) {
		if($token) {
			return array_merge(
				$this->getDefaultHeaders(),
				$this->getAuthorizationHeaders($token)
			);
		}

		return $this->getDefaultHeaders();
	}

	/**
	 * Get JWT verification keys.
	 *
	 * @return array
	 */
	public function getJwtVerificationKeys() {
		$factory = $this->getRequestFactory();
		$url = $this->getVerificationKeysUrl();
		$request = $factory->getRequestWithOptions(self::METHOD_GET, $url, []);
		$response = $this->getParsedResponse($request);

		$keys = [];

		if(!empty($response['keys'])){
			foreach($response['keys'] as $i => $keyinfo) {
				$keys[$keyinfo['kid']] = $this->decodeKey($keyinfo);
			}
		}

		return $keys;
	}

	/**
	 * Decodes a JWT verification key.
	 *
	 * @param $keyinfo array
	 * @return bool|string
	 */
	protected function decodeKey($keyinfo) {
		$modulus = $keyinfo['n'];
		$exponent = $keyinfo['e'];
		$rsa = new RSA();

		$modulus = new BigInteger(JWT::urlsafeB64Decode($modulus), 256);
		$exponent = new BigInteger(JWT::urlsafeB64Decode($exponent), 256);

		$publicKey = $rsa->_convertPublicKey($modulus, $exponent);
		$rsa->loadKey($publicKey);
		$rsa->setPublicKey();

		return $rsa->getPublicKey();
	}

	/**
	 * Returns the verification keys URL.
	 *
	 * @return string
	 */
	public function getVerificationKeysUrl() {
		$keysUrl = '';
		if(!empty($this->openidConfiguration['jwks_uri'])){
			$keysUrl = $this->openidConfiguration['jwks_uri'];
		}

		return $keysUrl;
	}

	/**
	 * Sets the openid configuration if a config array is provided, fetches and sets the info from
	 * openidConfigurationUrl otherwise.
	 *
	 * @param array $config
	 */
	protected function setOpenidConfiguration($config = []) {
		$this->openidConfiguration = empty($config) ? $this->fetchOpenidConfiguration() : $config;
	}

	/**
	 * Returns openid configuration.
	 *
	 * @return array
	 */
	public function getOpenidConfiguration() {
		return $this->openidConfiguration;
	}

	/**
	 * Fetches the Openid Configuration from the openid configuration URL.
	 *
	 * @return array
	 */
	protected function fetchOpenidConfiguration() {
		$factory = $this->getRequestFactory();
		$request = $factory->getRequestWithOptions('get', $this->getOpenidConfigurationUrl(), []);

		$response = $this->getParsedResponse($request);

		return $response;
	}

	/**
	 * Returns the openid configuration URL.
	 *
	 * @return string
	 */
	public function getOpenidConfigurationUrl() {
		return $this->openidConfigurationUrl;
	}

	/**
	 * Returns the current value of the state parameter if set.
	 * Otherwise creates, sets and returns a new one.
	 *
	 * @return string
	 */
	protected function getSessionState() {
		$this->state = $this->getSessionBasedRandomString(4);

		return $this->state;
	}

	/**
	 * Returns a session-based random string of roughly ($salt_length + session_id) length.
	 *
	 * @param int $salt_length
	 * @return string
	 */
	protected function getSessionBasedRandomString($salt_length = 32) {
		$session_id = session_id();
		$salt = bin2hex(random_bytes($salt_length));
		$random_str = $salt . '_' . sha1($session_id . $salt);

		return $random_str;
	}

	/**
	 * Validates a session-based random string created with getSessionBasedRandomString().
	 *
	 * @param $string
	 * @return bool
	 */
	protected function validateSessionBasedRandomString($string) {
		$session_id = session_id();
		list($salt, $hash) = explode('_', $string);

		if($hash == sha1($session_id . $salt)) {
			return true;
		}

		return false;
	}

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state) {
		return $this->validateSessionBasedRandomString($state);
	}

	/**
	 * Creates, sets and returns a session-based nonce.
	 *
	 * @return string
	 */
	protected function createNonce() {
		$this->nonce = $this->getSessionBasedRandomString(32);

		return $this->nonce;
	}

	/**
	 * Validates a session-based nonce.
	 *
	 * @param $nonce string
	 * @return bool
	 */
	public function validateNonce($nonce) {
		return $this->validateSessionBasedRandomString($nonce);
	}
}