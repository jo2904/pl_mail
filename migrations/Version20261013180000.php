<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Which OpenID Connect identity an account signs in as — see User::$oidcSubject.
 *
 * Two nullable columns and a unique index over the pair. Every existing row is
 * null in both, which is what "not linked yet" means: an account is linked the
 * first time its holder signs in through the provider, so nothing has to be
 * backfilled.
 *
 * Reversible; going down forgets every link, and each account is linked again
 * by address on its next sign-in through the provider.
 */
final class Version20261013180000 extends AbstractMigration
{
    public function getDescription(): string
    {
        return 'Link accounts to an OpenID Connect identity, so a single sign-on provider can sign them in';
    }

    public function up(Schema $schema): void
    {
        $this->addSql('ALTER TABLE "user" ADD oidc_issuer VARCHAR(255) DEFAULT NULL');
        $this->addSql('ALTER TABLE "user" ADD oidc_subject VARCHAR(255) DEFAULT NULL');
        $this->addSql('CREATE UNIQUE INDEX uniq_user_oidc_identity ON "user" (oidc_issuer, oidc_subject)');
    }

    public function down(Schema $schema): void
    {
        $this->addSql('DROP INDEX uniq_user_oidc_identity');
        $this->addSql('ALTER TABLE "user" DROP oidc_issuer');
        $this->addSql('ALTER TABLE "user" DROP oidc_subject');
    }
}
