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