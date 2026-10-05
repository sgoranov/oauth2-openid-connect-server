# OpenID Connect examples

These examples demonstrate this package with PHP 8.2+, OAuth2 Server 9 and Slim 4. They use in-memory repositories and hard-coded demo credentials, so they are for local development only. Do not use the repository implementations or credentials in production.

## Installation

From this directory, install the example application:

```bash
composer install
```

Generate a private signing key and restrict its permissions:

```bash
openssl genrsa -out private.key 2048
chmod 600 private.key
```

Configure an encryption password and the canonical issuer advertised to clients:

```bash
export OAUTH_ENCRYPTION_KEY="replace-with-a-long-random-secret"
export OIDC_ISSUER="https://localhost:4444"
```

Start the development server:

```bash
php -S localhost:4444 -t public
```

The built-in PHP server does not provide TLS. The `https://localhost:4444` issuer is illustrative; use a local TLS proxy or an issuer URL that exactly matches your test client's trusted configuration when validating ID tokens end to end.

## Password grant example

The password grant is retained only to demonstrate compatibility with OAuth2 Server. New applications should prefer the authorization-code grant with PKCE.

```bash
curl -X POST "http://localhost:4444/password.php/access_token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=myawesomeapp" \
    --data-urlencode "client_secret=abc123" \
    --data-urlencode "username=alex" \
    --data-urlencode "password=whisky" \
    --data-urlencode "scope=openid email"
```

## Client credentials example

Client credentials authenticate a client rather than an end user. Consequently, this endpoint returns an access token but not an OpenID Connect ID token.

```bash
curl -X POST "http://localhost:4444/client_credentials.php/access_token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=myawesomeapp" \
    --data-urlencode "client_secret=abc123" \
    --data-urlencode "scope=email"
```

The authorization-code and implicit examples expose `/authorize` routes in their corresponding scripts. The implicit flow is included for legacy interoperability only; new clients should use authorization code with PKCE.
