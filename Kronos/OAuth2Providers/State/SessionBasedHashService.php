<?php

namespace Kronos\OAuth2Providers\State;

class SessionBasedHashService implements StateServiceInterface, NonceServiceInterface
{


    private $saltLength;

    /**
     * @param int $saltLength
     */
    public function __construct(int $saltLength = 4)
    {
        $this->saltLength = $saltLength;
    }

    public function generateNonce(): string
    {
        return $this->generateHash();
    }

    public function validateNonce($nonce): bool
    {
        return $this->validateHash($nonce);
    }

    public function generateState(): string
    {
        return $this->generateHash();
    }

    public function validateState($state): bool
    {
        return $this->validateHash($state);
    }


    protected function generateHash(): string
    {
        $session_id = session_id();
        $salt = bin2hex(random_bytes($this->saltLength));
        return $salt . '_' . sha1($session_id . $salt);
    }


    protected function validateHash($state): bool
    {
        $session_id = session_id();
        [$salt, $hash] = explode('_', $state);

        if ($hash === sha1($session_id . $salt)) {
            return true;
        }

        return false;
    }

    /**
     * @return int
     */
    public function getSaltLength(): int
    {
        return $this->saltLength;
    }

    /**
     * @param int $saltLength
     */
    public function setSaltLength($saltLength)
    {
        $this->saltLength = $saltLength;
    }
}
