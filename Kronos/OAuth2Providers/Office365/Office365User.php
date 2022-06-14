<?php

namespace Kronos\OAuth2Providers\Office365;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class Office365User implements ResourceOwnerInterface
{
    /**
     * Response data
     *
     * @var array
     */
    protected $response;

    /**
     * Constructor
     *
     * @param array $response Response data
     */
    public function __construct(array $response)
    {
        $this->response = $response;
    }

    /**
     * @inheritdoc
     */
    public function getId()
    {
        return $this->getProperty('Id');
    }

    /**
     * @inheritdoc
     */
    public function toArray()
    {
        return $this->response;
    }

    /**
     * Returns the name displayed in the address book for the user. This is
     * usually the combination of the user's first name, middle initial and
     * last name.
     *
     * @return null|string displayName
     */
    public function getDisplayName()
    {
        return $this->getProperty('DisplayName');
    }

    /**
     * Returns email address (may be same as UserPrincipalName)
     *
     * @return null|string mail
     */
    public function getEmail()
    {
        return $this->getProperty('EmailAddress');
    }

    /**
     * Returns the user principal name (UPN) of the user. This *should* map to
     * the user's email name.
     *
     * @return null|string userPrincipalName
     */
    public function getPrincipalName()
    {
        return $this->getProperty('EmailAddress');
    }

    /**
     * Gets property value
     *
     * @param string $property Property name
     * @param mixed $default Default value to return if property does not exist
     * @return mixed
     */
    public function getProperty($property, $default = null)
    {
        return $this->response[$property] ?? $default;
    }
}
