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

	/**
	 * (oid) The immutable identifier for an object in the Microsoft identity system, in this case, a user account.
	 * @return string
	 */
	public function getId()
	{
		return $this->response['oid'];
	}

	/**
	 * (tid) A GUID that represents the Azure AD tenant that the user is from. For work and school accounts, the GUID is the immutable tenant ID of the organization that the user belongs to.
	 */
	public function getTenantId()
	{
		$this->response['tid'];
	}

	/**
	 * The name claim provides a human-readable value that identifies the subject of the token.
	 *
	 * @return string|null
	 */
	public function getName()
	{
		return $this->response['name'];
	}

	/**
	 * @return string|null
	 */
	public function getFirstName()
	{
		return $this->response['given_name'];
	}

	public function getLastName()
	{
		return $this->response['family_name'];
	}

	/**
	 * (upn) Get email address.
	 *
	 * @return string|null
	 */
	public function getEmail()
	{
		return $this->response['upn'];
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