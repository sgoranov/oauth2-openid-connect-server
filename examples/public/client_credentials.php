<?php

declare(strict_types=1);

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use OpenIDConnectServerExamples\Repositories\AccessTokenRepository;
use OpenIDConnectServerExamples\Repositories\ClientRepository;
use OpenIDConnectServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$encryptionKey = getenv('OAUTH_ENCRYPTION_KEY')
    ?: throw new RuntimeException('Set the OAUTH_ENCRYPTION_KEY environment variable.');

// Client credentials authenticate a client, not an end user, so this example
// intentionally uses the default bearer-token response without an ID token.
$server = new AuthorizationServer(
    new ClientRepository(),
    new AccessTokenRepository(),
    new ScopeRepository(),
    'file://' . __DIR__ . '/../private.key',
    $encryptionKey
);
$server->enableGrantType(new ClientCredentialsGrant(), new DateInterval('PT1H'));

$app = AppFactory::create();
$app->setBasePath('/client_credentials.php');
$app->addErrorMiddleware(true, true, true);

$app->post('/access_token', function (
    ServerRequestInterface $request,
    ResponseInterface $response
) use ($server): ResponseInterface {
    try {
        return $server->respondToAccessTokenRequest($request, $response);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

$app->run();
