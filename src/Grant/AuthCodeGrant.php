<?php

declare(strict_types=1);

namespace OpenIDConnectServer\Grant;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Grant\AuthCodeGrant as LeagueAuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends LeagueAuthCodeGrant
{
    public function __construct(
        \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface $authCodeRepository,
        \League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface $refreshTokenRepository,
        private DateInterval $oidcAuthCodeTTL
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $oidcAuthCodeTTL);
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new AuthorizationRequest();
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);
        $nonce = $this->getQueryStringParameter('nonce', $request);

        if ($nonce !== null) {
            /** @var AuthorizationRequest $authorizationRequest */
            $authorizationRequest->setNonce($nonce);
        }

        return $authorizationRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if ($authorizationRequest->getUser() instanceof UserEntityInterface === false) {
            throw new LogicException('An instance of UserEntityInterface should be set on the AuthorizationRequest');
        }

        $finalRedirectUri = $authorizationRequest->getRedirectUri()
            ?? $this->getClientRedirectUri($authorizationRequest->getClient());

        if ($authorizationRequest->isAuthorizationApproved() === true) {
            $authCode = $this->issueAuthCode(
                $this->oidcAuthCodeTTL,
                $authorizationRequest->getClient(),
                $authorizationRequest->getUser()->getIdentifier(),
                $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getScopes()
            );

            return $this->createAuthorizationCodeResponse($authorizationRequest, $authCode, $finalRedirectUri);
        }

        throw \League\OAuth2\Server\Exception\OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri($finalRedirectUri, ['state' => $authorizationRequest->getState()])
        );
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        $this->setResponseNonceFromAuthorizationCode($request, $responseType);

        return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
    }

    private function createAuthorizationCodeResponse(
        AuthorizationRequestInterface $authorizationRequest,
        \League\OAuth2\Server\Entities\AuthCodeEntityInterface $authCode,
        string $redirectUri
    ): ResponseTypeInterface {
        $payload = [
            'client_id'             => $authCode->getClient()->getIdentifier(),
            'redirect_uri'          => $authCode->getRedirectUri(),
            'auth_code_id'          => $authCode->getIdentifier(),
            'scopes'                => $authCode->getScopes(),
            'user_id'               => $authCode->getUserIdentifier(),
            'expire_time'           => (new DateTimeImmutable())->add($this->oidcAuthCodeTTL)->getTimestamp(),
            'code_challenge'        => $authorizationRequest->getCodeChallenge(),
            'code_challenge_method' => $authorizationRequest->getCodeChallengeMethod(),
            'nonce'                 => $authorizationRequest instanceof AuthorizationRequest
                ? $authorizationRequest->getNonce()
                : null,
        ];

        $jsonPayload = json_encode($payload);
        if ($jsonPayload === false) {
            throw new LogicException('An error was encountered when JSON encoding the authorization request response');
        }

        $response = new RedirectResponse();
        $response->setRedirectUri($this->makeRedirectUri(
            $redirectUri,
            [
                'code'  => $this->encrypt($jsonPayload),
                'state' => $authorizationRequest->getState(),
            ]
        ));

        return $response;
    }

    private function setResponseNonceFromAuthorizationCode(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType
    ): void {
        if (!$responseType instanceof IdTokenResponse) {
            return;
        }

        $parsedBody = (array) $request->getParsedBody();
        $code = $parsedBody['code'] ?? null;
        if (!is_string($code)) {
            return;
        }

        try {
            $payload = json_decode($this->decrypt($code));
        } catch (\Throwable) {
            // Let the League grant produce its normal invalid-code response.
            return;
        }

        if (is_object($payload) && property_exists($payload, 'nonce')) {
            $responseType->setNonce(is_string($payload->nonce) ? $payload->nonce : null);
        }
    }
}
