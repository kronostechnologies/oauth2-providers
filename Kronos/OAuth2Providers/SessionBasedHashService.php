<?php

namespace Kronos\OAuth2Providers;

class SessionBasedHashService {

	/**
	 * Returns a session-based random string of roughly ($salt_length + session_id) length.
	 *
	 * @param int $salt_length
	 * @return string
	 */
	public function getSessionBasedHash($salt_length = 32) {
		$session_id = session_id();
		$salt = bin2hex(random_bytes($salt_length));
		$random_str = $salt . '_' . sha1($session_id . $salt);

		return $random_str;
	}

	/**
	 * Validates a session-based hash.
	 *
	 * @param $string
	 * @return bool
	 */
	public function validateSessionBasedHash($string) {
		$session_id = session_id();
		list($salt, $hash) = explode('_', $string);

		if($hash == sha1($session_id . $salt)) {
			return true;
		}

		return false;
	}
}