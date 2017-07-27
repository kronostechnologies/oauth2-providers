<?php

namespace Kronos\OAuth2Providers\Auth0;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class Auth0User implements ResourceOwnerInterface {

	/**
	 * @var array
	 */
	protected $response;

	/**
	 * @param array $response
	 */
	public function __construct(array $response) {
		$this->response = $response;
	}

	/**
	 * Returns the identifier of the authorized resource owner.
	 *
	 * @return mixed
	 */
	public function getId() {
		return $this->response['user_id'];
	}

	/**
	 * Get name.
	 *
	 * @return string
	 */
	public function getName() {
		return $this->response['name'];
	}

	/**
	 * Get avatar image URL.
	 *
	 * @return string|null
	 */
	public function getAvatar() {
		return $this->response['picture'];
	}

	/**
	 * Get user data as an array.
	 *
	 * @return array
	 */
	public function toArray() {
		return $this->response;
	}
}