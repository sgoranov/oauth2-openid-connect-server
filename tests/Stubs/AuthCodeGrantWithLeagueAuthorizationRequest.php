<?php

namespace OpenIDConnectServer\Test\Stubs;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use OpenIDConnectServer\Grant\AuthCodeGrant;

/**
 * Overrides createAuthorizationRequest() with a request that can't carry a nonce,
 * as a consumer subclass might.
 */
class AuthCodeGrantWithLeagueAuthorizationRequest extends AuthCodeGrant
{
    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new AuthorizationRequest();
    }
}
