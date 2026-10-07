<?php

declare(strict_types=1);

namespace OpenIDConnectServer\Grant;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant as LeagueAuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use OpenIDConnectServer\IdTokenResponse;
use OpenIDConnectServer\RequestTypes\AuthorizationRequest;
use Psr\Http\Message\ServerRequestInterface;

class AuthCodeGrant extends LeagueAuthCodeGrant
{
    /**
     * Maximum nonce length in bytes. OIDC sets no limit; this keeps the encrypted
     * authorization code, and so the redirect URL, within common URL length limits.
     */
    public const MAX_NONCE_LENGTH = 255;

    /**
     * Overrides League's constructor.
     *
     * League keeps the auth code TTL in a private property, so it's captured here as well:
     * completeAuthorizationRequest() needs it to issue codes.
     */
    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private DateInterval $oidcAuthCodeTTL
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $oidcAuthCodeTTL);
    }

    /**
     * Overrides League's AbstractAuthorizeGrant::createAuthorizationRequest().
     *
     * Returns this package's AuthorizationRequest, which can carry the OIDC nonce.
     */
    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new AuthorizationRequest();
    }

    /**
     * Overrides League's validateAuthorizationRequest().
     *
     * League doesn't know about the OIDC nonce parameter. After League's own validation,
     * this reads the nonce from the query string for OpenID requests and stores it on the request.
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $authorizationRequest = parent::validateAuthorizationRequest($request);

        // nonce is an OpenID Connect parameter; plain OAuth 2.0 requests must ignore it (RFC 6749 §3.1).
        if (!$this->isOpenIdRequest($authorizationRequest)) {
            return $authorizationRequest;
        }

        // Read the raw value: the ID token must echo the nonce exactly (OIDC Core §3.1.3.7),
        // so League's trimming getQueryStringParameter() is not used here.
        $nonce = $request->getQueryParams()['nonce'] ?? null;
        if ($nonce !== null && !is_string($nonce)) {
            throw OAuthServerException::invalidRequest('nonce');
        }

        if ($nonce !== null && strlen($nonce) > self::MAX_NONCE_LENGTH) {
            throw OAuthServerException::invalidRequest(
                'nonce',
                sprintf('The nonce must not exceed %d bytes', self::MAX_NONCE_LENGTH)
            );
        }

        if ($nonce !== null && $nonce !== '') {
            /** @var AuthorizationRequest $authorizationRequest */
            $authorizationRequest->setNonce($nonce);
        }

        return $authorizationRequest;
    }

    /**
     * Overrides League's completeAuthorizationRequest().
     *
     * League builds the encrypted code payload inline and offers no hook to extend it.
     * This copy (mirroring league/oauth2-server 9.4.1) adds the nonce to the payload,
     * and must be kept in sync with upstream changes.
     */
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

        throw OAuthServerException::accessDenied(
            'The user denied the request',
            $this->makeRedirectUri($finalRedirectUri, ['state' => $authorizationRequest->getState()])
        );
    }

    /**
     * Overrides League's respondToAccessTokenRequest().
     *
     * Passes the nonce from the validated authorization code to IdTokenResponse,
     * so it appears as the nonce claim in the issued ID token.
     */
    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL
    ): ResponseTypeInterface {
        if ($responseType instanceof IdTokenResponse) {
            // Reset first so a nonce from an earlier exchange can never carry over.
            $responseType->setNonce(null);
        }

        $responseType = parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);

        // The parent has validated the code, client, redirect URI and PKCE by now, so the code
        // decrypts cleanly and the nonce comes from a fully verified payload. League exposes no
        // hook for the payload it already decrypted, so the code is decrypted a second time here.
        if ($responseType instanceof IdTokenResponse) {
            $code = (string) $this->getRequestParameter('code', $request);
            $responseType->setNonce($this->extractNonce($this->decrypt($code)));
        }

        return $responseType;
    }

    private function createAuthorizationCodeResponse(
        AuthorizationRequestInterface $authorizationRequest,
        AuthCodeEntityInterface $authCode,
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

    private function extractNonce(string $authCodePayloadJson): ?string
    {
        $payload = json_decode($authCodePayloadJson);
        if (!is_object($payload) || !property_exists($payload, 'nonce')) {
            return null;
        }

        return is_string($payload->nonce) ? $payload->nonce : null;
    }

    private function isOpenIdRequest(AuthorizationRequestInterface $authorizationRequest): bool
    {
        foreach ($authorizationRequest->getScopes() as $scope) {
            if ($scope->getIdentifier() === 'openid') {
                return true;
            }
        }

        return false;
    }
}
