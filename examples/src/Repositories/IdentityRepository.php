<?php

declare(strict_types=1);

namespace OpenIDConnectServerExamples\Repositories;

use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use OpenIDConnectServerExamples\Entities\UserEntity;

class IdentityRepository implements IdentityProviderInterface
{
    public function getUserEntityByIdentifier($identifier): UserEntity
    {
        return new UserEntity((string) $identifier);
    }
}
