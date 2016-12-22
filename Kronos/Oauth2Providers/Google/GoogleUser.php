<?php
/**
 * Created by PhpStorm.
 * User: mdemers
 * Date: 2016-12-22
 * Time: 10:46 AM
 */

namespace Kronos\Oauth2Providers\Google;


use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class GoogleUser implements ResourceOwnerInterface{
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