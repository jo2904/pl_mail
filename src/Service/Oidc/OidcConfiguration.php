<?php

declare(strict_types=1);

namespace App\Service\Oidc;

use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * How this install signs people in through an OpenID Connect provider, if it
 * does — Authentik, Keycloak, Authelia, Zitadel and the like.
 *
 * Read from the environment and nowhere else. The other OAuth clients here
 * (Google, Microsoft) can be entered under Admin → Integrations as well, but
 * those connect mailboxes once somebody is already signed in; this decides who
 * may sign in at all, and a setting an administrator can change from inside
 * the session it governs is one a stolen admin session can use to let itself
 * back in. The environment is held by whoever runs the server.
 *
 * Off unless all three of issuer, client id and secret are set. A half-filled
 * configuration shows no button rather than one that fails at the provider.
 */
final readonly class OidcConfiguration
{
    /** @var list<string> */
    public array $scopes;

    public function __construct(
        #[Autowire('%env(OIDC_ISSUER)%')]
        public string $issuer,
        #[Autowire('%env(OIDC_CLIENT_ID)%')]
        public string $clientId,
        #[Autowire('%env(OIDC_CLIENT_SECRET)%')]
        #[\SensitiveParameter]
        public string $clientSecret,
        #[Autowire('%env(OIDC_BUTTON_LABEL)%')]
        public string $buttonLabel,
        #[Autowire('%env(bool:OIDC_AUTO_CREATE)%')]
        public bool $autoCreate,
        #[Autowire('%env(bool:OIDC_REQUIRE_VERIFIED_EMAIL)%')]
        public bool $requireVerifiedEmail,
        #[Autowire('%env(OIDC_SCOPES)%')]
        string $scopes,
    ) {
        $requested = preg_split('/[\s,]+/', $scopes, -1, PREG_SPLIT_NO_EMPTY) ?: [];

        // `openid` is what makes the request an OpenID Connect one at all —
        // without it the provider answers with a plain OAuth token and no ID
        // token, and the failure reads as the provider misbehaving. So it is
        // added rather than required of whoever writes the variable.
        $this->scopes = array_values(array_unique(['openid', ...$requested]));
    }

    public function isEnabled(): bool
    {
        return '' !== $this->issuer && '' !== $this->clientId && '' !== $this->clientSecret;
    }
}
