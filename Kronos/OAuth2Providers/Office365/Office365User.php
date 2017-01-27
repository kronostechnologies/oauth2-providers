<?php

namespace Kronos\OAuth2Providers\Office365;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class Office365User implements ResourceOwnerInterface  {

	/**
	 * @var array
	 */
	protected $response;

	/**
	 * @param array $response
	 */
	public function __construct(array $response)
	{
		$this->response = $response;
	}

	public function getId()
	{
		return $this->response['objectId'];
	}

	/**
	 * Get perferred display name.
	 *
	 * @return string
	 */
	public function getName()
	{
		return $this->response['givenName'] != '' ? $this->response['givenName'] : $this->response['displayName'];
	}

	/**
	 * Get email address.
	 *
	 * @return string|null
	 */
	public function getEmail()
	{
		return $this->response['mail'];
	}

	/**
	 * Get user data as an array.
	 *
	 * @return array
	 */
	public function toArray()
	{
		return $this->response;
	}
}