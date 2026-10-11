<?php

namespace OpenIDConnectServer\Test\Stubs;

use League\OAuth2\Server\CryptTrait;
use OpenIDConnectServer\Grant\AuthCodeGrant;

/**
 * Overrides decrypt() without calling the parent, as a consumer subclass might.
 */
class AuthCodeGrantWithOwnDecrypt extends AuthCodeGrant
{
    protected function decrypt(string $encryptedData): string
    {
        $crypt = new class {
            use CryptTrait {
                decrypt as public;
            }
        };
        $crypt->setEncryptionKey($this->encryptionKey);

        return $crypt->decrypt($encryptedData);
    }
}
