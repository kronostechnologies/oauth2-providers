<?php

namespace Kronos\OAuth2Providers\State;

class SessionBasedHashService implements StateServiceInterface, NonceServiceInterface {


    private $saltLength=32;

    /**
     * @param int $saltLength
     */
    public function __construct($saltLength = 32)
    {
        $this->saltLength = $saltLength;
    }

    public function generateNonce()
    {
        return $this->generateHash();
    }

    public function validateNonce($nonce)
    {
        return $this->validateHash($nonce);
    }

    public function generateState()
    {
        return $this->generateHash();
    }

    public function validateState($state)
    {
        return $this->validateHash($state);
    }


    protected function generateHash() {
        $salt_length = 32;
		$session_id = session_id();
		$salt = bin2hex(random_bytes($salt_length));
		$random_str = $salt . '_' . sha1($session_id . $salt);
		return $random_str;
	}


    protected function validateHash($state) {
		$session_id = session_id();
		list($salt, $hash) = explode('_', $state);

		if($hash == sha1($session_id . $salt)) {
			return true;
		}

		return false;
	}

    /**
     * @return int
     */
    public function getSaltLength()
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