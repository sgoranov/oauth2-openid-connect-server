# OAuth 2.0 OpenID Connect Server

[![PHPUnit Tests](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/phpunit.yml/badge.svg?branch=master)](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/phpunit.yml)
[![Dependency Vulnerability Scan](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/vulnerability-scan.yml/badge.svg?branch=master)](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/vulnerability-scan.yml)

This library adds OpenID Connect ID tokens and scope-based user claims to [The PHP League's OAuth2 Server](https://github.com/thephpleague/oauth2-server).

## Why this fork exists

This is a fork maintained by [Simeon Goranov](https://github.com/sgoranov), based on [Steve Rhoades' original project](https://github.com/steverhoades/oauth2-openid-connect-server). The original project established the OpenID Connect integration, but its dependency and API compatibility layers targeted older versions of PHP, OAuth2 Server and `lcobucci/jwt`.

This fork continues that work for modern applications by:

- requiring PHP 8.2 or later;
- targeting OAuth2 Server 9 and `lcobucci/jwt` 5.6;
- **resolving the ID-token issuer explicitly instead of trusting the incoming `Host` header;**
- **propagating authorization-request nonces into signed ID tokens for authorization-code flows;**
- **returning the granted `scope` in every token response, as RFC 6749 requires when it differs from the requested scope;**
- removing obsolete compatibility paths and unused APIs; and
- providing a self-contained PHPUnit and Docker test workflow.

These updates include breaking changes from the original package, particularly the `IdTokenResponse` constructor and supported dependency versions. See [Migrating from steverhoades/oauth2-openid-connect-server](#migrating-from-steverhoadesoauth2-openid-connect-server).

## Requirements

- PHP 8.2 or later
- [`league/oauth2-server`](https://github.com/thephpleague/oauth2-server) 9.0.1 or later
- [`lcobucci/jwt`](https://github.com/lcobucci/jwt) 5.6 or later

## Install

Install the latest compatible 1.x release with Composer:

```bash
composer require sgoranov/oauth2-openid-connect-server:^1.0
```

## Usage

This library plugs into League's `AuthorizationServer` as its response type. Besides the repositories League already needs, you provide a user entity that exposes claims and an identity provider that looks users up. A runnable Slim application with in-memory implementations is in [`examples/`](examples/).

| Component | Provided by | Purpose |
| --- | --- | --- |
| `IdTokenResponse` | This library | The server's response type. Adds `id_token` and `scope` to token responses. |
| `Grant\AuthCodeGrant` | This library | Replaces League's `AuthCodeGrant` and carries the authorization request's `nonce` into the ID token. |
| `ClaimExtractor` | This library | Decides which user claims each granted scope releases. |
| `StaticIssuerResolver` | This library | Supplies the issuer (`iss`). Implement `IssuerResolverInterface` instead to serve several issuers. |
| User entity | You | Implements `UserEntityInterface` and `ClaimSetInterface`, and returns the user's claims. |
| Identity provider | You | Implements `IdentityProviderInterface` and loads a user entity by its identifier. |
| Scope repository | You, already required by League | Must recognize the `openid` scope. |

### 1. Recognize the `openid` scope

Your scope repository's `getScopeEntityByIdentifier()` must return a scope entity for `openid`. If it returns `null`, League rejects requests for that scope with `invalid_scope` and no ID token is issued. The same applies to `profile`, `email` and any custom scope whose claims you want to release. See [`ScopeRepository`](examples/src/Repositories/ScopeRepository.php) in the examples.

### 2. Expose users and their claims

Your user entity implements League's `UserEntityInterface` and this library's `ClaimSetInterface`. `getClaims()` returns the user's attributes as claim name and value pairs; the granted scopes decide which of them reach the ID token.

```php
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;

class UserEntity implements UserEntityInterface, ClaimSetInterface
{
    use EntityTrait;

    protected array $attributes = [];

    public function getClaims(): array
    {
        return $this->attributes;
    }
}
```

Your identity provider implements `OpenIDConnectServer\Repositories\IdentityProviderInterface`. Its one method, `getUserEntityByIdentifier($identifier)`, receives the access token's user identifier and returns that user's entity. Return `null` if the user no longer exists; the token request then fails with `invalid_grant`. An entity that does not implement both interfaces causes a `RuntimeException`.

### 3. Choose which claims each scope releases

A claim set ties a scope to the claims it releases. `ClaimExtractor` comes with the four scopes defined by OpenID Connect:

| Scope | Claims |
| --- | --- |
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email` | `email`, `email_verified` |
| `address` | `address` |
| `phone` | `phone_number`, `phone_number_verified` |

These four are reserved: passing a claim set for one of them throws `OpenIDConnectServer\Exception\InvalidArgumentException`. Add your own scopes through the constructor or `addClaimSet()`:

```php
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetEntity;

$claimExtractor = new ClaimExtractor([
    new ClaimSetEntity('company', ['company_name', 'company_phone', 'company_address']),
]);
```

A token granted `openid company` then carries whichever of those claims the user's `getClaims()` returns. Every ID token also carries the registered claims `iss`, `sub`, `aud`, `iat` and `exp`, with `exp` matching the access token's expiry.

### 4. Configure the server

```php
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Grant\AuthCodeGrant;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\StaticIssuerResolver;

// Init Repositories
$clientRepository       = new ClientRepository();
$scopeRepository        = new ScopeRepository();
$accessTokenRepository  = new AccessTokenRepository();
$authCodeRepository     = new AuthCodeRepository();
$refreshTokenRepository = new RefreshTokenRepository();

$privateKey = new CryptKey('file://' . __DIR__ . '/../private.key');
$encryptionKey = $_ENV['OAUTH_ENCRYPTION_KEY'];

// OpenID Connect Response Type
$issuerResolver = new StaticIssuerResolver('https://auth.example.com');
$responseType = new IdTokenResponse(
    new IdentityRepository(),
    new ClaimExtractor(),
    $issuerResolver
);

// Setup the authorization server
$server = new AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey,
    $responseType
);

$grant = new AuthCodeGrant(
    $authCodeRepository,
    $refreshTokenRepository,
    new \DateInterval('PT10M') // authorization codes will expire after 10 minutes
);

$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

// Enable the authentication code grant on the server
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);

return $server;
```

`IdTokenResponse` adds an `id_token` to every token response whose access token was granted `openid` and belongs to a user. Access tokens without a user, such as those from the `client_credentials` grant, get no `id_token`. It also adds `scope` to every response, as described in [Granted scope](#granted-scope). To set the ID token's `kid` header, pass the key identifier as a fourth constructor argument.

Use `OpenIDConnectServer\Grant\AuthCodeGrant` instead of League's grant for authorization-code flows, so that nonces reach the ID token (see [Nonces](#nonces)). It requires `IdTokenResponse` as the server's response type, and throws a `LogicException` on token requests otherwise.

Once configured, use the server as described in the [OAuth2 Server documentation](https://oauth2.thephpleague.com/).

### Nonces

`OpenIDConnectServer\Grant\AuthCodeGrant` takes the same constructor arguments as League's `AuthCodeGrant`. It preserves an optional `nonce` authorization parameter in the encrypted authorization code and adds the same value to the resulting ID token.

For nonce support, include a `nonce` parameter in the authorization request, for example `GET /authorize?response_type=code&client_id=client-id&scope=openid&nonce=random-request-value`. The client should generate a unique value for each request and verify that the ID token's `nonce` claim matches it. Nonces longer than 255 bytes (`AuthCodeGrant::MAX_NONCE_LENGTH`) or not valid UTF-8 are rejected with an `invalid_request` error, redirected to the client's redirect URI with its `state`.

Nonce support covers the authorization-code flow only. The OpenID Connect implicit flow (`response_type=id_token`) is not supported; League's `ImplicitGrant` issues access tokens only, without an ID token.

### Granted scope

Every token response from `IdTokenResponse` includes a `scope` parameter: the space-separated scopes on the issued access token, after the server's `finalizeScopes()` has run. It is included for every grant, whether or not `openid` was requested:

```json
{
    "token_type": "Bearer",
    "expires_in": 3600,
    "access_token": "...",
    "scope": "openid email",
    "id_token": "..."
}
```

RFC 6749 §5.1 requires `scope` whenever the server grants different scopes from those requested. League doesn't pass the requested scopes to the response type, so `scope` is always included. Clients can use it to see what was actually granted. For example, if `openid` was removed, that explains why the response has no `id_token`. When no scopes were granted, `scope` is an empty string.

Subclasses that override `getExtraParams()` should merge their parameters with `parent::getExtraParams($accessToken)` so `scope` and `id_token` are kept.

### Issuer resolution

The issuer must be the canonical URL advertised by the OpenID Provider and must exactly match the value expected by clients. `StaticIssuerResolver` is suitable for a single-issuer server:

```php
$issuerResolver = new StaticIssuerResolver('https://auth.example.com');
```

Multi-tenant servers can implement `IssuerResolverInterface` and resolve an issuer from trusted access-token context:

```php
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use OpenIDConnectServer\IssuerResolverInterface;

final class TenantIssuerResolver implements IssuerResolverInterface
{
    /** @param array<string, string> $trustedIssuersByClient */
    public function __construct(
        private readonly array $trustedIssuersByClient
    ) {
    }

    // The access token holds the private key; keep it out of exception traces.
    public function resolve(#[\SensitiveParameter] AccessTokenEntityInterface $accessToken): string
    {
        $clientId = $accessToken->getClient()->getIdentifier();

        return $this->trustedIssuersByClient[$clientId]
            ?? throw new RuntimeException('No trusted issuer configured for this client.');
    }
}
```

Do not build the issuer from `$_SERVER['HTTP_HOST']` or another untrusted request header.

## Migrating from steverhoades/oauth2-openid-connect-server

### Replace the package

This fork keeps the original `OpenIDConnectServer\` namespace, so the two packages cannot be installed side by side. Composer enforces this through a `conflict` rule: remove the original package before requiring this one.

```bash
composer remove steverhoades/oauth2-openid-connect-server
composer require sgoranov/oauth2-openid-connect-server:^1.0
```

If another dependency requires the original package, Composer will refuse the installation instead of loading two copies of the same classes.

### `IdTokenResponse` constructor (breaking)

The ID-token issuer is no longer taken from the incoming `Host` header. `IdTokenResponse` now requires an `IssuerResolverInterface` as its third argument, and the optional key identifier (`kid`) moves from third to fourth position.

Before:

```php
$responseType = new IdTokenResponse(
    new IdentityRepository(),
    new ClaimExtractor(),
    'my-key-id' // optional kid
);
```

After:

```php
$responseType = new IdTokenResponse(
    new IdentityRepository(),
    new ClaimExtractor(),
    new StaticIssuerResolver('https://auth.example.com'),
    'my-key-id' // optional kid
);
```

Code that passed a key identifier positionally now fails with a `TypeError`, because a string is not an `IssuerResolverInterface`. Code that passed no key identifier fails with an `ArgumentCountError`. See [Issuer resolution](#issuer-resolution) for choosing a resolver.

### Nonce support

To include the authorization-request `nonce` in ID tokens, replace League's `AuthCodeGrant` with `OpenIDConnectServer\Grant\AuthCodeGrant`. It takes the same constructor arguments. Without this change, the server keeps working but ID tokens carry no `nonce` claim.

## Testing

Run the complete test workflow in Docker:

```bash
./bin/test-run
```

Alternatively, with PHP and Composer installed locally:

```bash
composer install
composer test
```

The tests use project-owned fixtures and do not require OAuth2 Server's internal test suite or a source installation.

## License

The MIT License (MIT). Please see the [license file](LICENSE) for more information.
