<?php

declare(strict_types=1);

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\PasswordGrant;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\StaticIssuerResolver;
use OpenIDConnectServerExamples\Repositories\AccessTokenRepository;
use OpenIDConnectServerExamples\Repositories\ClientRepository;
use OpenIDConnectServerExamples\Repositories\IdentityRepository;
use OpenIDConnectServerExamples\Repositories\RefreshTokenRepository;
use OpenIDConnectServerExamples\Repositories\ScopeRepository;
use OpenIDConnectServerExamples\Repositories\UserRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$encryptionKey = getenv('OAUTH_ENCRYPTION_KEY')
    ?: throw new RuntimeException('Set the OAUTH_ENCRYPTION_KEY environment variable.');
$issuer = getenv('OIDC_ISSUER')
    ?: throw new RuntimeException('Set the OIDC_ISSUER environment variable.');

$passwordGrant = new PasswordGrant(
    new UserRepository(),
    new RefreshTokenRepository()
);
$passwordGrant->setRefreshTokenTTL(new DateInterval('P1M'));

$server = new AuthorizationServer(
    new ClientRepository(),
    new AccessTokenRepository(),
    new ScopeRepository(),
    'file://' . __DIR__ . '/../private.key',
    $encryptionKey,
    new IdTokenResponse(
        new IdentityRepository(),
        new ClaimExtractor(),
        new StaticIssuerResolver($issuer)
    )
);
$server->enableGrantType($passwordGrant, new DateInterval('PT1H'));

$app = AppFactory::create();
$app->setBasePath('/password.php');
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
