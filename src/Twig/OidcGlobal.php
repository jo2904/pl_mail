<?php

declare(strict_types=1);

namespace App\Twig;

use App\Service\Oidc\OidcConfiguration;

/**
 * Whether the login page offers single sign-on, and what its button says.
 *
 * A global, like `demo`, which the same page already asks the same kind of
 * question of — one way for the login template to learn what this install
 * offers, rather than one global and one controller variable.
 */
final readonly class OidcGlobal
{
    public function __construct(
        private OidcConfiguration $configuration,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->configuration->isEnabled();
    }

    /**
     * The provider's name as the operator wants it on the button, or null for
     * the generic wording.
     */
    public function label(): ?string
    {
        return '' === trim($this->configuration->buttonLabel) ? null : $this->configuration->buttonLabel;
    }
}
