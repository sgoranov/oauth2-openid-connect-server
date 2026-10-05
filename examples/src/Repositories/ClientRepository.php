<?php

declare(strict_types=1);

namespace OpenIDConnectServerExamples\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OpenIDConnectServerExamples\Entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface
{
    private const CLIENT_ID = 'myawesomeapp';
    private const CLIENT_SECRET = 'abc123';

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        if ($clientIdentifier !== self::CLIENT_ID) {
            return null;
        }

        $client = new ClientEntity();
        $client->setIdentifier(self::CLIENT_ID);
        $client->setName('My Awesome App');
        $client->setRedirectUri('http://localhost:4444/auth_code.php/callback');
        $client->setConfidential();

        return $client;
    }

    public function validateClient(
        string $clientIdentifier,
        ?string $clientSecret,
        ?string $grantType
    ): bool {
        return $clientIdentifier === self::CLIENT_ID
            && hash_equals(self::CLIENT_SECRET, $clientSecret ?? '');
    }
}
