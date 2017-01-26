<?php
/**
 * Created by PhpStorm.
 * User: mdemers
 * Date: 2017-01-26
 * Time: 9:38 AM
 */

namespace Kronos\OAuth2Providers\Office365;


use TheNetworg\OAuth2\Client\Provider\AzureResourceOwner;

class Office365User extends AzureResourceOwner {

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
		return $this->response['id'];
	}

	/**
	 * Get perferred display name.
	 *
	 * @return string
	 */
	public function getName()
	{
		return $this->response['name'];
	}

	/**
	 * Get perferred first name.
	 *
	 * @return string
	 */
	public function getFirstName()
	{
		return $this->response['givenName'];
	}

	/**
	 * Get perferred last name.
	 *
	 * @return string
	 */
	public function getLastName()
	{
		return $this->response['familyName'];
	}

	/**
	 * Get email address.
	 *
	 * @return string|null
	 */
	public function getEmail()
	{
		return $this->response['email'];
	}

	/**
	 * Get avatar image URL.
	 *
	 * @return string|null
	 */
	public function getAvatar()
	{
		return $this->response['picture']['url'];
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