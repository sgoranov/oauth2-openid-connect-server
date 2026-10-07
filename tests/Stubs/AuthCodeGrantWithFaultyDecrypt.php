<?php

namespace OpenIDConnectServer\Test\Stubs;

use Error;
use OpenIDConnectServer\Grant\AuthCodeGrant;

/**
 * Throws an unexpected error on the first decrypt() call only, simulating a
 * programming bug that must not be mistaken for an invalid authorization code.
 */
class AuthCodeGrantWithFaultyDecrypt extends AuthCodeGrant
{
    private bool $failed = false;

    protected function decrypt(string $encryptedData): string
    {
        if (!$this->failed) {
            $this->failed = true;
            throw new Error('Unexpected failure while decrypting');
        }

        return parent::decrypt($encryptedData);
    }
}
