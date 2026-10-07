<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace OpenIDConnectServer;

use Lcobucci\JWT\Signer\Key\InMemory;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Encoding\JoseEncoder;

class IdTokenResponse extends BearerTokenResponse
{
    private ?string $nonce = null;

    public function __construct(
        protected IdentityProviderInterface $identityProvider,
        protected ClaimExtractor $claimExtractor,
        protected IssuerResolverInterface $issuerResolver,
        protected ?string $keyIdentifier = null
    ) {
    }

    public function setNonce(?string $nonce): void
    {
        $this->nonce = $nonce;
    }

    protected function getBuilder(AccessTokenEntityInterface $accessToken, UserEntityInterface $userEntity)
    {
        $claimsFormatter = ChainedFormatter::withUnixTimestampDates();
        $builder = new Builder(new JoseEncoder(), $claimsFormatter);

        // Add required id_token claims
        return $builder
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->issuedBy($this->issuerResolver->resolve($accessToken))
            ->issuedAt(new \DateTimeImmutable())
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($userEntity->getIdentifier());
    }

    /**
     * Adds the granted scope to every token response, and an id_token to OpenID Connect responses.
     *
     * RFC 6749 §5.1 requires scope whenever the granted scopes differ from those requested.
     * League doesn't pass the requested scopes to the response type, so scope is always included.
     *
     * @param AccessTokenEntityInterface $accessToken
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $params = parent::getExtraParams($accessToken);
        $params['scope'] = $this->formatScopes($accessToken->getScopes());

        if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
            return $params;
        }

        /** @var UserEntityInterface $userEntity */
        $userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

        if (false === is_a($userEntity, UserEntityInterface::class)) {
            throw new \RuntimeException('UserEntity must implement UserEntityInterface');
        } else if (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new \RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        // Add required id_token claims
        $builder = $this->getBuilder($accessToken, $userEntity);

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

        foreach ($claims as $claimName => $claimValue) {
            $builder = $builder->withClaim($claimName, $claimValue);
        }

        if ($this->nonce !== null) {
            $builder = $builder->withClaim('nonce', $this->nonce);
        }

        if ($this->keyIdentifier !== null) {
            $builder = $builder->withHeader('kid', $this->keyIdentifier);
        }

        $key = InMemory::plainText(
            $this->privateKey->getKeyContents(),
            (string) $this->privateKey->getPassPhrase()
        );

        $token = $builder->getToken(new Sha256(), $key);

        $params['id_token'] = $token->toString();

        return $params;
    }

    /**
     * Formats scopes as the space-separated list defined by RFC 6749 §3.3.
     *
     * @param ScopeEntityInterface[] $scopes
     */
    private function formatScopes(array $scopes): string
    {
        return implode(' ', array_map(
            static fn (ScopeEntityInterface $scope): string => $scope->getIdentifier(),
            $scopes
        ));
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return bool
     */
    private function isOpenIDRequest(array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }

        return false;
    }
}
