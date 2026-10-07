<?php

declare(strict_types=1);

namespace OpenIDConnectServer\RequestTypes;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as LeagueAuthorizationRequest;

class AuthorizationRequest extends LeagueAuthorizationRequest
{
    private ?string $nonce = null;

    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }
}
