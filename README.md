# OAuth 2.0 OpenID Connect Server

[![PHPUnit Tests](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/phpunit.yml/badge.svg?branch=main)](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/phpunit.yml)
[![Dependency Vulnerability Scan](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/vulnerability-scan.yml/badge.svg?branch=main)](https://github.com/sgoranov/oauth2-openid-connect-server/actions/workflows/vulnerability-scan.yml)

This library adds OpenID Connect ID tokens and scope-based user claims to [The PHP League's OAuth2 Server](https://github.com/thephpleague/oauth2-server).

## Why this fork exists

This is a fork maintained by [Simeon Goranov](https://github.com/sgoranov), based on [Steve Rhoades' original project](https://github.com/steverhoades/oauth2-openid-connect-server). The original project established the OpenID Connect integration, but its dependency and API compatibility layers targeted older versions of PHP, OAuth2 Server and `lcobucci/jwt`.

This fork continues that work for modern applications by:

- requiring PHP 8.2 or later;
- targeting OAuth2 Server 9 and `lcobucci/jwt` 5.6;
- **resolving the ID-token issuer explicitly instead of trusting the incoming `Host` header;**
- **propagating authorization-request nonces into signed ID tokens for authorization-code flows;**
- removing obsolete compatibility paths and unused APIs; and
- providing a self-contained PHPUnit and Docker test workflow.

These updates include breaking changes from the original package, particularly the `IdTokenResponse` constructor and supported dependency versions.

## Requirements

- PHP 8.2 or later
- [`league/oauth2-server`](https://github.com/thephpleague/oauth2-server) 9.x
- [`lcobucci/jwt`](https://github.com/lcobucci/jwt) 5.6 or later

## Usage

The following classes will need to be configured and passed to the AuthorizationServer in order to provide OpenID Connect functionality.

1. IdentityRepository.  This MUST implement the OpenIDConnectServer\Repositories\IdentityProviderInterface and return the identity of the user based on the return value of $accessToken->getUserIdentifier().
   1. The IdentityRepository MUST return a UserEntity that implements the following interfaces
      1. OpenIDConnectServer\Entities\ClaimSetInterface
      1. League\OAuth2\Server\Entities\UserEntityInterface.
1. ClaimSet.  ClaimSet is a way to associate claims to a given scope.
1. ClaimExtractor. The ClaimExtractor takes an array of ClaimSets and in addition provides default claims for the OpenID Connect specified scopes of: profile, email, phone and address.
1. IssuerResolver. This returns the canonical OpenID Provider issuer for an access token.
1. IdTokenResponse. This class must be passed to the AuthorizationServer during construction and is responsible for adding the `id_token` to the response.
1. ScopeRepository. The getScopeEntityByIdentifier($identifier) method must return a ScopeEntity for the `openid` scope in order to enable support. See examples.

### Example Configuration

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

Use the package-provided `OpenIDConnectServer\Grant\AuthCodeGrant` for authorization-code flows. It preserves an optional `nonce` authorization parameter in the encrypted authorization code and adds the same value to the resulting ID token.

For nonce support, include a `nonce` parameter in the authorization request, for example `GET /authorize?response_type=code&client_id=client-id&scope=openid&nonce=random-request-value`. The client should generate a unique value for each request and verify that the ID token's `nonce` claim matches it. Nonces longer than 255 bytes (`AuthCodeGrant::MAX_NONCE_LENGTH`) are rejected with `invalid_request`.

Nonce support covers the authorization-code flow only. The OpenID Connect implicit flow (`response_type=id_token`) is not supported; League's `ImplicitGrant` issues access tokens only, without an ID token.

After the server has been configured it should be used as described in the [OAuth2 Server documentation](https://oauth2.thephpleague.com/).

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

    public function resolve(AccessTokenEntityInterface $accessToken): string
    {
        $clientId = $accessToken->getClient()->getIdentifier();

        return $this->trustedIssuersByClient[$clientId]
            ?? throw new RuntimeException('No trusted issuer configured for this client.');
    }
}
```

Do not build the issuer from `$_SERVER['HTTP_HOST']` or another untrusted request header.

## UserEntity

In order for this library to work properly you will need to add your IdentityProvider to the IdTokenResponse object. This will be used internally to look up a UserEntity by its identifier. Additionally, your UserEntity must implement the ClaimSetInterface which includes a single method getClaims(). The getClaims() method should return a list of attributes as key/value pairs that can be returned if the proper scope has been defined.

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

## ClaimSets

A ClaimSet is a scope that defines a list of claims.

```php
// Example of the profile ClaimSet
$claimSet = new ClaimSetEntity('profile', [
    'name',
    'family_name',
    'given_name',
    'middle_name',
    'nickname',
    'preferred_username',
    'profile',
    'picture',
    'website',
    'gender',
    'birthdate',
    'zoneinfo',
    'locale',
    'updated_at'
]);
```

As you can see from the above, profile lists a set of claims that can be extracted from our UserEntity if the profile scope is included with the authorization request.

### Adding Custom ClaimSets

At some point you will likely want to include your own group of custom claims. To do this you will need to create a ClaimSetEntity, give it a scope (the value you will include in the scope parameter of your OAuth2 request) and the list of claims it supports.

```php
$extractor = new ClaimExtractor();
// Create your custom scope
$claimSet = new ClaimSetEntity('company', [
    'company_name',
    'company_phone',
    'company_address'
]);

// Add it to the ClaimExtractor passed to IdTokenResponse.
$extractor->addClaimSet($claimSet);
```

Now, when you pass the company scope with your request it will attempt to locate those properties from your UserEntity::getClaims().

## Install

Install the latest compatible 1.x release with Composer:

```bash
composer require sgoranov/oauth2-openid-connect-server:^1.0
```

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
