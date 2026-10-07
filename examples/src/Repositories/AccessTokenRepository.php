<?php

declare(strict_types=1);

namespace OpenIDConnectServerExamples\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use OpenIDConnectServerExamples\Entities\AccessTokenEntity;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null
    ): AccessTokenEntityInterface {
        $token = new AccessTokenEntity();
        $token->setClient($clientEntity);

        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }

        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
    }

    public function revokeAccessToken(string $tokenId): void
    {
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return false;
    }
}
