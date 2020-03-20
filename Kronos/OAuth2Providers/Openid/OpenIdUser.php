<?php


namespace Kronos\OAuth2Providers\Openid;


use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class OpenIdUser implements ResourceOwnerInterface
{
    /**
     * Informations returned by the userinfo endpoint
     * @var array
     */
    private $userInfoResponse;

    public function __construct(array $userInfoResponse)
    {
        $this->userInfoResponse = $userInfoResponse;
    }

    public function getId()
    {
        return $this->userInfoResponse['sub'] ?? null;
    }

    public function toArray()
    {
        return $this->userInfoResponse;
    }

}
