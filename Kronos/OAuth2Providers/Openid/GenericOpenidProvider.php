<?php

namespace Kronos\OAuth2Providers\Openid;

use Firebase\JWT\JWT;
use GuzzleHttp\Exception\BadResponseException;
use InvalidArgumentException;
use Kronos\OAuth2Providers\Openid\IdToken\IdToken;
use Kronos\OAuth2Providers\OpenidServiceInterface;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use UnexpectedValueException;

class GenericOpenidProvider implements OpenidServiceInterface {

	use ArrayAccessorTrait;
	use QueryBuilderTrait;

	/**
	 * @var OpenidProviderOptions
	 */
	protected $options;

	/**
	 * @var array
	 */
	protected $openidConfiguration;

	/**
	 * @var OpenidProviderCollaborators
	 */
	protected $collaborators;

	/**
	 * Constructs an Openid Connect service provider.
	 *
	 * @param OpenidProviderOptions $options
	 * @param OpenidProviderCollaborators $collaborators
	 */
	public function __construct(OpenidProviderOptions $options, OpenidProviderCollaborators $collaborators) {
		$this->collaborators = $collaborators ?: new OpenidProviderCollaborators();
		$this->collaborators->getGrantFactory()->setGrant('jwt_bearer', new JwtBearer);

		if(!$options) {
			throw new InvalidArgumentException('$option argument must be a valid OpenidProviderOptions instance');
		}
		$this->options = $options;
		$this->openidConfiguration = $this->fetchOpenidConfiguration();
	}

	/**
	 * Builds the authorization URL.
	 *
	 * @return string Authorization URL
	 */
	public function getAuthorizationUrl() {
		$url = $this->getAuthorizationEndpoint();
		$params = $this->getAuthorizationParameters();
		$query = $this->buildQueryString($params);

		return $this->appendQuery($url, $query);
	}

	/**
	 * Returns the base URL for authorizing a client.
	 *
	 * @return string
	 */
	protected function getAuthorizationEndpoint() {
		return $this->openidConfiguration['authorization_endpoint'];
	}

	/**
	 * Returns the default scopes used by this provider.
	 *
	 * @return array
	 */
	protected function getDefaultScopes() {
		return ['openid'];
	}

	/**
	 * Returns the string that should be used to separate scopes when building
	 * the URL for requesting an id token.
	 *
	 * @return string Scope separator, defaults to ','
	 */
	protected function getScopeSeparator() {
		return ',';
	}

	/**
	 * Returns authorization parameters.
	 *
	 * @return array Authorization parameters
	 */
	protected function getAuthorizationParameters() {
		$options = [];

		$options['state'] = $this->collaborators->getHashService()->getSessionBasedHash();

		$options['nonce'] = $this->collaborators->getHashService()->getSessionBasedHash();

		$options['response_type'] = 'code';
		$options['approval_prompt'] = 'auto';

		$options['scope'] = $this->getDefaultScopes();
		if(is_array($options['scope'])) {
			$separator = $this->getScopeSeparator();
			$options['scope'] = implode($separator, $options['scope']);
		}

		$options['redirect_uri'] = $this->options->getRedirectUri();
		$options['client_id'] = $this->options->getClientId();

		return $options;
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
	 * Requests and creates an id token.
	 *
	 * @param $grant
	 * @param array $options
	 * @return IdToken
	 */
	public function getIdToken($grant, array $options = []) {
		$parsed = $this->getIdTokenParsedResponse($grant, $options);

		return $this->createIdToken($parsed);
	}

	/**
	 * Requests an id token and returns the parsed response.
	 *
	 * @param $grant
	 * @param array $options
	 * @return array
	 */
	protected function getIdTokenParsedResponse($grant, array $options = []) {
		$grant = $this->verifyGrant($grant);

		$params = [
			'client_id' => $this->options->getClientId(),
			'client_secret' => $this->options->getClientSecret(),
			'redirect_uri' => $this->options->getRedirectUri()
		];

		$params = $grant->prepareRequestParameters($params, $options);
		$request = $this->getIdTokenRequest($params);
		$response = $this->getParsedResponse($request);

		return $response;
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
			return $this->collaborators->getGrantFactory()->getGrant($grant);
		}

		$this->collaborators->getGrantFactory()->checkGrant($grant);
		return $grant;
	}

	/**
	 * Returns a prepared request for requesting an id token.
	 *
	 * @param array $params Query string parameters
	 * @return RequestInterface
	 */
	protected function getIdTokenRequest(array $params) {
		$method = 'POST';
		$url = $this->getTokenEndpoint();
		$options = $this->getIdTokenOptions($params);

		return $this->getRequest($method, $url, $options);
	}

	/**
	 * Sends a request and returns the parsed response.
	 *
	 * @param  RequestInterface $request
	 * @return mixed
	 */
	protected function getParsedResponse(RequestInterface $request) {
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
	 * Returns the base URL for requesting an access token.
	 *
	 * @return string
	 */
	protected function getTokenEndpoint() {
		return $this->openidConfiguration['token_endpoint'];
	}

	/**
	 * Builds request options used for requesting an id token.
	 *
	 * @param  array $params
	 * @return array
	 */
	protected function getIdTokenOptions(array $params) {
		$options = ['headers' => ['content-type' => 'application/x-www-form-urlencoded']];
		$options['body'] = $this->buildQueryString($params);

		return $options;
	}

	/**
	 * Returns a PSR-7 request instance.
	 *
	 * @param  string $method
	 * @param  string $url
	 * @param  array $options
	 * @return RequestInterface
	 */
	protected function getRequest($method, $url, array $options = []) {
		return $this->createRequest($method, $url, null, $options);
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

		return $this->collaborators->getRequestFactory()->getRequestWithOptions($method, $url, $options);
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
	protected function getResponse(RequestInterface $request) {
		return $this->collaborators->getHttpClient()->send($request);
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
	 * Returns all headers used by this provider for a request.
	 *
	 * The request will be authenticated if an id token is provided.
	 *
	 * @param  mixed|null $token object or string
	 * @return array
	 */
	protected function getHeaders($token = null) {
		if($token) {
			return array_merge(
				$this->getDefaultHeaders(),
				$this->getAuthorizationHeaders($token)
			);
		}

		return $this->getDefaultHeaders();
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
	 * Creates an id token from a response.
	 *
	 * The provider that was used to fetch the response can be used to provide
	 * additional context.
	 *
	 * @param  array $response
	 * @return IdToken
	 */
	protected function createIdToken(array $response) {
		return $this->collaborators->getIdTokenFactory()->createIdToken($response['id_token'], $this->getJwtVerificationKeys(), $this->options->getClientId(), $this->openidConfiguration['issuer']);
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
	 * Get JWT verification keys.
	 *
	 * @return array
	 */
	protected function getJwtVerificationKeys() {
		$request = $this->collaborators->getRequestFactory()->getRequestWithOptions('GET', $this->openidConfiguration['jwks_uri']);
		$response = $this->getParsedResponse($request);

		$keys = [];

		if(!empty($response['keys'])) {
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
	 * Fetches the Openid Configuration from the openid configuration URL.
	 *
	 * @return array
	 */
	protected function fetchOpenidConfiguration() {
		$request = $this->collaborators->getRequestFactory()->getRequestWithOptions('get', $this->options->getOpenidConfigurationUrl(), []);
		$response = $this->getParsedResponse($request);

		return $response;
	}

	/**
	 * @param string $state
	 * @return bool
	 */
	public function validateSate($state) {
		return $this->collaborators->getHashService()->validateSessionBasedHash($state);
	}
}