<?php

declare(strict_types=1);

namespace OpenIDConnectServerExamples\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OpenIDConnectServerExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    public function getUserEntityByUserCredentials(
        string $username,
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity
    ): ?UserEntityInterface {
        if ($username !== 'alex' || $password !== 'whisky') {
            return null;
        }

        return new UserEntity();
    }
}
