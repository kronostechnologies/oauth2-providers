<?php

namespace Kronos\OAuth2Providers\Openid;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class OpenIdUser implements ResourceOwnerInterface {

	/**
	 * @var IdToken
	 */
	protected $id_token;

	/**
	 * AzureAdUser constructor.
	 * @param IdToken $id_token
	 */
	public function __construct(IdToken $id_token) {
		$this->id_token = $id_token;
	}

	/**
	 * Returns the identifier of the authorized resource owner.
	 *
	 * @return mixed
	 */
	public function getId() {
		return $this->id_token->getUserId();
	}

	/**
	 * Return all of the owner details available as an array.
	 *
	 * @return array
	 */
	public function toArray() {
		return $this->id_token->getClaims();
	}
}