<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace OpenIDConnectServer;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

final class StaticIssuerResolver implements IssuerResolverInterface
{
    public function __construct(private readonly string $issuer)
    {
    }

    public function resolve(AccessTokenEntityInterface $accessToken): string
    {
        return $this->issuer;
    }
}
