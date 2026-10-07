<?php

declare(strict_types=1);

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ImplicitGrant;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\StaticIssuerResolver;
use OpenIDConnectServerExamples\Entities\UserEntity;
use OpenIDConnectServerExamples\Repositories\AccessTokenRepository;
use OpenIDConnectServerExamples\Repositories\ClientRepository;
use OpenIDConnectServerExamples\Repositories\IdentityRepository;
use OpenIDConnectServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';

$encryptionKey = getenv('OAUTH_ENCRYPTION_KEY')
    ?: throw new RuntimeException('Set the OAUTH_ENCRYPTION_KEY environment variable.');
$issuer = getenv('OIDC_ISSUER')
    ?: throw new RuntimeException('Set the OIDC_ISSUER environment variable.');

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
$server->enableGrantType(new ImplicitGrant(new DateInterval('PT1H')));

$app = AppFactory::create();
$app->setBasePath('/implicit.php');
$app->addErrorMiddleware(true, true, true);

$app->get('/authorize', function (
    ServerRequestInterface $request,
    ResponseInterface $response
) use ($server): ResponseInterface {
    try {
        $authRequest = $server->validateAuthorizationRequest($request);
        $authRequest->setUser(new UserEntity());
        $authRequest->setAuthorizationApproved(true);

        return $server->completeAuthorizationRequest($authRequest, $response);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    }
});

$app->run();
