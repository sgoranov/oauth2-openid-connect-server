<?php
/**
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 */
namespace OpenIDConnectServer;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

interface IssuerResolverInterface
{
    public function resolve(AccessTokenEntityInterface $accessToken): string;
}
