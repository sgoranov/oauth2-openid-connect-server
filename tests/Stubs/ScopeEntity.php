<?php

namespace OpenIDConnectServer\Test\Stubs;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
