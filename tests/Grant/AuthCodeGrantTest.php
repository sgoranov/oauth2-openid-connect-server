<?php

namespace OpenIDConnectServer\Test\Grant;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Grant\AuthCodeGrant;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\RequestTypes\AuthorizationRequest;
use OpenIDConnectServer\StaticIssuerResolver;
use OpenIDConnectServer\Test\Stubs\AccessTokenEntity;
use OpenIDConnectServer\Test\Stubs\AuthCodeEntity;
use OpenIDConnectServer\Test\Stubs\ClientEntity;
use OpenIDConnectServer\Test\Stubs\IdentityProvider;
use OpenIDConnectServer\Test\Stubs\ScopeEntity;
use OpenIDConnectServer\Test\Stubs\UserEntity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthCodeGrantTest extends TestCase
{
    private const ENCRYPTION_KEY = 'test-encryption-password';
    private const CLIENT_ID = 'test-client';
    private const REDIRECT_URI = 'https://client.example/callback';

    private CryptKey $privateKey;
    private AuthCodeGrant $grant;

    protected function setUp(): void
    {
        $this->privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');
        $this->grant = $this->createGrant();
    }

    public function testNonceFlowsFromAuthorizationRequestIntoIssuedIdToken(): void
    {
        $nonce = 'unique-request-nonce';

        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => $nonce])
        );
        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertSame($nonce, $authorizationRequest->getNonce());

        $code = $this->approveAndGetCode($authorizationRequest);
        $idToken = $this->exchangeCodeForIdToken($code);

        self::assertSame($nonce, $idToken->claims()->get('nonce'));
        self::assertTrue($this->signatureIsValid($idToken));
    }

    public function testIdTokenSignatureCoversNonceClaim(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'original-nonce']);
        $rawIdToken = $this->exchangeCode($code)->id_token;

        $segments = explode('.', $rawIdToken);
        $payload = json_decode(base64_decode(strtr($segments[1], '-_', '+/')), true);
        $payload['nonce'] = 'tampered-nonce';
        $encodedPayload = json_encode($payload);
        self::assertIsString($encodedPayload);
        $segments[1] = rtrim(strtr(base64_encode($encodedPayload), '+/', '-_'), '=');

        self::assertFalse($this->signatureIsValid($this->parseIdToken(implode('.', $segments))));
    }

    public function testIdTokenHasNoNonceClaimWhenNonceWasNotRequested(): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest($this->authorizationServerRequest());
        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertNull($authorizationRequest->getNonce());

        $idToken = $this->exchangeCodeForIdToken($this->approveAndGetCode($authorizationRequest));

        self::assertFalse($idToken->claims()->has('nonce'));
    }

    #[DataProvider('provideBlankNonces')]
    public function testBlankNonceIsTreatedAsAbsent(string $nonce): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => $nonce])
        );
        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertNull($authorizationRequest->getNonce());

        $idToken = $this->exchangeCodeForIdToken($this->approveAndGetCode($authorizationRequest));

        self::assertFalse($idToken->claims()->has('nonce'));
    }

    public static function provideBlankNonces(): array
    {
        return [
            'empty string' => [''],
            'whitespace only' => ["  \t "],
        ];
    }

    public function testSurroundingWhitespaceIsTrimmedFromNonce(): void
    {
        $idToken = $this->exchangeCodeForIdToken($this->authorizeAndGetCode(['nonce' => '  padded-nonce  ']));

        self::assertSame('padded-nonce', $idToken->claims()->get('nonce'));
    }

    public function testArrayNonceIsRejectedAsInvalidRequest(): void
    {
        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3); // invalid_request

        $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => ['first', 'second']])
        );
    }

    #[DataProvider('provideOpaqueNonces')]
    public function testNonceValueIsPreservedVerbatim(string $nonce): void
    {
        $idToken = $this->exchangeCodeForIdToken($this->authorizeAndGetCode(['nonce' => $nonce]));

        self::assertSame($nonce, $idToken->claims()->get('nonce'));
    }

    public static function provideOpaqueNonces(): array
    {
        return [
            'url reserved characters' => ['a+b/c=d&e?f#g%20h'],
            'json special characters' => ['"quoted" \\ back\\slash'],
            'unicode' => ['nonce-ünïcødé-🔐'],
            'base64url random' => [rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=')],
            'long value' => [str_repeat('n', 2048)],
        ];
    }

    public function testNonceIsNotExposedInAuthorizationRedirect(): void
    {
        $nonce = 'secret-nonce-value';
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => $nonce, 'state' => 'abc'])
        );
        $authorizationRequest->setUser(new UserEntity());
        $authorizationRequest->setAuthorizationApproved(true);

        $location = $this->grant->completeAuthorizationRequest($authorizationRequest)
            ->generateHttpResponse(new Response())
            ->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $redirectParams);

        self::assertStringStartsWith(self::REDIRECT_URI, $location);
        self::assertSame(['code', 'state'], array_keys($redirectParams));
        self::assertSame('abc', $redirectParams['state']);
        self::assertStringNotContainsString($nonce, $location);
        self::assertStringNotContainsString('nonce', $location);
    }

    public function testNonceIsStoredInsideEncryptedAuthorizationCode(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'stored-nonce']);

        self::assertStringNotContainsString('stored-nonce', $code);

        $payload = json_decode($this->crypt()->decrypt($code), true);
        self::assertSame('stored-nonce', $payload['nonce']);
        self::assertSame(self::CLIENT_ID, $payload['client_id']);
        self::assertSame(['openid'], $payload['scopes']);
    }

    public function testAuthorizationCodeStoresNullNonceWhenNotRequested(): void
    {
        $payload = json_decode($this->crypt()->decrypt($this->authorizeAndGetCode()), true);

        self::assertArrayHasKey('nonce', $payload);
        self::assertNull($payload['nonce']);
    }

    public function testStateAndNonceAreHandledIndependently(): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => 'the-nonce', 'state' => 'the-state'])
        );
        $authorizationRequest->setUser(new UserEntity());
        $authorizationRequest->setAuthorizationApproved(true);

        $location = $this->grant->completeAuthorizationRequest($authorizationRequest)
            ->generateHttpResponse(new Response())
            ->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $redirectParams);

        self::assertSame('the-state', $redirectParams['state']);

        $idToken = $this->exchangeCodeForIdToken($redirectParams['code']);
        self::assertSame('the-nonce', $idToken->claims()->get('nonce'));
        self::assertFalse($idToken->claims()->has('state'));
    }

    public function testNonceSurvivesPkceFlow(): void
    {
        $codeVerifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        $code = $this->authorizeAndGetCode([
            'nonce' => 'pkce-nonce',
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        $idToken = $this->parseIdToken(
            $this->exchangeCode($code, ['code_verifier' => $codeVerifier])->id_token
        );

        self::assertSame('pkce-nonce', $idToken->claims()->get('nonce'));
    }

    public function testNonceIsNotIssuedWhenPkceVerificationFails(): void
    {
        $codeVerifier = rtrim(strtr(base64_encode(random_bytes(48)), '+/', '-_'), '=');
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        $code = $this->authorizeAndGetCode([
            'nonce' => 'pkce-nonce',
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        $this->expectException(OAuthServerException::class);

        $this->exchangeCode($code, ['code_verifier' => str_repeat('x', 64)]);
    }

    public function testNonceIsNotStoredOnAuthorizationRequestWithoutOpenidScope(): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => 'oauth-only-nonce', 'scope' => 'email'])
        );

        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertNull($authorizationRequest->getNonce());
    }

    public function testNonceIsNotStoredInAuthorizationCodeWithoutOpenidScope(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'oauth-only-nonce', 'scope' => 'email']);

        self::assertStringNotContainsString('oauth-only-nonce', $this->crypt()->decrypt($code));
        $payload = json_decode($this->crypt()->decrypt($code), true);
        self::assertNull($payload['nonce']);
        self::assertSame(['email'], $payload['scopes']);
    }

    public function testPlainOAuthRequestWithNonceIssuesAccessTokenWithoutIdToken(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'oauth-only-nonce', 'scope' => 'email']);

        $response = $this->exchangeCode($code);

        self::assertObjectHasProperty('access_token', $response);
        self::assertObjectNotHasProperty('id_token', $response);
    }

    public function testMalformedNonceIsIgnoredWithoutOpenidScope(): void
    {
        // Unrecognised parameters must be ignored for plain OAuth 2.0 requests, even when malformed.
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => ['first', 'second'], 'scope' => 'email'])
        );

        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertNull($authorizationRequest->getNonce());
    }

    #[DataProvider('provideScopesIncludingOpenid')]
    public function testNonceIsStoredWhenOpenidIsAmongRequestedScopes(string $scope): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => 'mixed-scope-nonce', 'scope' => $scope])
        );
        self::assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);
        self::assertSame('mixed-scope-nonce', $authorizationRequest->getNonce());

        $idToken = $this->exchangeCodeForIdToken($this->approveAndGetCode($authorizationRequest));
        self::assertSame('mixed-scope-nonce', $idToken->claims()->get('nonce'));
    }

    public static function provideScopesIncludingOpenid(): array
    {
        return [
            'openid first' => ['openid email'],
            'openid last' => ['email openid'],
        ];
    }

    public function testPlainBearerResponseTypeIsUnaffectedByNonce(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'bearer-nonce']);

        $responseType = new BearerTokenResponse();
        $response = $this->exchangeCode($code, [], $responseType);

        self::assertObjectHasProperty('access_token', $response);
        self::assertObjectNotHasProperty('id_token', $response);
    }

    public function testMalformedCodeResultsInOAuthErrorRatherThanNonceFailure(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->exchangeCode('not-a-valid-encrypted-code');
    }

    public function testCodeEncryptedWithDifferentKeyIsRejected(): void
    {
        $code = $this->authorizeAndGetCode(['nonce' => 'foreign-nonce']);

        $otherGrant = $this->createGrant('another-encryption-password');

        $this->expectException(OAuthServerException::class);

        $otherGrant->respondToAccessTokenRequest(
            new ServerRequest(parsedBody: ['client_id' => self::CLIENT_ID, 'code' => $code]),
            $this->createIdTokenResponse(),
            new DateInterval('PT1H')
        );
    }

    public function testLegacyCodeWithoutNonceKeyIssuesIdTokenWithoutNonce(): void
    {
        // Codes issued before nonce support (e.g. by the upstream League grant) have no nonce key.
        $code = $this->crypt()->encrypt((string) json_encode([
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => null,
            'auth_code_id' => 'legacy-code',
            'scopes' => ['openid'],
            'user_id' => '123',
            'expire_time' => (new DateTimeImmutable('+10 minutes'))->getTimestamp(),
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));

        $idToken = $this->exchangeCodeForIdToken($code);

        self::assertFalse($idToken->claims()->has('nonce'));
    }

    public function testReusedIdTokenResponseDoesNotLeakNonceBetweenExchanges(): void
    {
        $responseType = $this->createIdTokenResponse();

        $first = $this->exchangeCode($this->authorizeAndGetCode(['nonce' => 'first-nonce']), [], $responseType);
        self::assertSame('first-nonce', $this->parseIdToken($first->id_token)->claims()->get('nonce'));

        $second = $this->exchangeCode($this->authorizeAndGetCode(), [], $responseType);
        self::assertFalse($this->parseIdToken($second->id_token)->claims()->has('nonce'));
    }

    public function testEachAuthorizationKeepsItsOwnNonce(): void
    {
        $codeA = $this->authorizeAndGetCode(['nonce' => 'nonce-a']);
        $codeB = $this->authorizeAndGetCode(['nonce' => 'nonce-b']);

        self::assertSame('nonce-b', $this->exchangeCodeForIdToken($codeB)->claims()->get('nonce'));
        self::assertSame('nonce-a', $this->exchangeCodeForIdToken($codeA)->claims()->get('nonce'));
    }

    public function testDeniedAuthorizationRedirectsWithAccessDeniedAndState(): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => 'denied-nonce', 'state' => 'denied-state'])
        );
        $authorizationRequest->setUser(new UserEntity());
        $authorizationRequest->setAuthorizationApproved(false);

        try {
            $this->grant->completeAuthorizationRequest($authorizationRequest);
            self::fail('Expected access_denied exception');
        } catch (OAuthServerException $exception) {
            self::assertSame('access_denied', $exception->getErrorType());
            $location = $exception->generateHttpResponse(new Response())->getHeaderLine('Location');
            self::assertStringContainsString('state=denied-state', $location);
            self::assertStringNotContainsString('denied-nonce', $location);
        }
    }

    public function testCompletingAuthorizationWithoutUserThrows(): void
    {
        $authorizationRequest = $this->grant->validateAuthorizationRequest(
            $this->authorizationServerRequest(['nonce' => 'no-user-nonce'])
        );
        $authorizationRequest->setAuthorizationApproved(true);

        $this->expectException(\LogicException::class);

        $this->grant->completeAuthorizationRequest($authorizationRequest);
    }

    private function createGrant(string $encryptionKey = self::ENCRYPTION_KEY): AuthCodeGrant
    {
        $client = new ClientEntity();
        $client->setIdentifier(self::CLIENT_ID);
        $client->setRedirectUri(self::REDIRECT_URI);

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn($client);

        $scopeRepository = $this->createMock(ScopeRepositoryInterface::class);
        $scopeRepository->method('getScopeEntityByIdentifier')->willReturnCallback(
            static function (string $identifier): ?ScopeEntity {
                if (!in_array($identifier, ['openid', 'email'], true)) {
                    return null;
                }

                $scope = new ScopeEntity();
                $scope->setIdentifier($identifier);

                return $scope;
            }
        );
        $scopeRepository->method('finalizeScopes')->willReturnCallback(
            static fn (array $scopes): array => $scopes
        );

        $authCodeRepository = $this->createMock(AuthCodeRepositoryInterface::class);
        $authCodeRepository->method('getNewAuthCode')->willReturnCallback(
            static fn (): AuthCodeEntity => new AuthCodeEntity()
        );
        $authCodeRepository->method('isAuthCodeRevoked')->willReturn(false);

        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->method('getNewRefreshToken')->willReturn(null);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->method('getNewToken')->willReturnCallback(
            static function (
                ClientEntityInterface $clientEntity,
                array $scopes,
                ?string $userIdentifier
            ): AccessTokenEntityInterface {
                $accessToken = new AccessTokenEntity();
                $accessToken->setClient($clientEntity);
                $accessToken->setUserIdentifier($userIdentifier);
                foreach ($scopes as $scope) {
                    $accessToken->addScope($scope);
                }

                return $accessToken;
            }
        );

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $refreshTokenRepository,
            new DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepository);
        $grant->setScopeRepository($scopeRepository);
        $grant->setAccessTokenRepository($accessTokenRepository);
        $grant->setDefaultScope('');
        $grant->setEncryptionKey($encryptionKey);
        $grant->setPrivateKey($this->privateKey);
        $grant->disableRequireCodeChallengeForPublicClients();

        return $grant;
    }

    private function createIdTokenResponse(): IdTokenResponse
    {
        return new IdTokenResponse(
            new IdentityProvider(),
            new ClaimExtractor(),
            new StaticIssuerResolver('https://issuer.example.test')
        );
    }

    private function authorizationServerRequest(array $queryParams = []): ServerRequest
    {
        return new ServerRequest(queryParams: $queryParams + [
            'response_type' => 'code',
            'client_id' => self::CLIENT_ID,
            'scope' => 'openid',
        ]);
    }

    private function authorizeAndGetCode(array $queryParams = []): string
    {
        return $this->approveAndGetCode(
            $this->grant->validateAuthorizationRequest($this->authorizationServerRequest($queryParams))
        );
    }

    private function approveAndGetCode($authorizationRequest): string
    {
        $authorizationRequest->setUser(new UserEntity());
        $authorizationRequest->setAuthorizationApproved(true);

        $location = $this->grant->completeAuthorizationRequest($authorizationRequest)
            ->generateHttpResponse(new Response())
            ->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $redirectParams);
        self::assertArrayHasKey('code', $redirectParams);

        return $redirectParams['code'];
    }

    private function exchangeCode(
        string $code,
        array $extraBody = [],
        ?ResponseTypeInterface $responseType = null
    ): object {
        $responseType ??= $this->createIdTokenResponse();
        $responseType->setPrivateKey($this->privateKey);

        $responseType = $this->grant->respondToAccessTokenRequest(
            new ServerRequest(parsedBody: $extraBody + [
                'client_id' => self::CLIENT_ID,
                'code' => $code,
            ]),
            $responseType,
            new DateInterval('PT1H')
        );

        $httpResponse = $responseType->generateHttpResponse(new Response());
        $httpResponse->getBody()->rewind();

        return json_decode($httpResponse->getBody()->getContents());
    }

    private function exchangeCodeForIdToken(string $code): UnencryptedToken
    {
        $response = $this->exchangeCode($code);
        self::assertObjectHasProperty('id_token', $response);

        return $this->parseIdToken($response->id_token);
    }

    private function parseIdToken(string $jwt): UnencryptedToken
    {
        $token = (new Parser(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates()))->parse($jwt);
        self::assertInstanceOf(UnencryptedToken::class, $token);

        return $token;
    }

    private function signatureIsValid(UnencryptedToken $token): bool
    {
        return (new Validator())->validate(
            $token,
            new SignedWith(new Sha256(), InMemory::file(__DIR__ . '/../Stubs/public.key'))
        );
    }

    private function crypt(): object
    {
        $crypt = new class {
            use CryptTrait {
                encrypt as public;
                decrypt as public;
            }
        };
        $crypt->setEncryptionKey(self::ENCRYPTION_KEY);

        return $crypt;
    }
}
