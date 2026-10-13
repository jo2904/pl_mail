# Single sign-on (OpenID Connect)

plMail can let people sign in through an identity provider you already run — Authentik, Keycloak,
Authelia, Zitadel, or anything else that speaks OpenID Connect. The login page then shows a
**Sign in with …** button above the password form; the password form stays.

This is about signing in to plMail itself. Connecting a Gmail or Outlook *mailbox* is a different
OAuth flow, on [Google](google.md) and [Microsoft](microsoft.md).

## What it does

- The authorisation code flow, with PKCE, a `state` and a `nonce`. The provider's endpoints are read
  from its discovery document, so the only address you configure is the issuer.
- An account is matched to the provider's identity by its **issuer and subject** (`sub`), which is
  stored on the account the first time that person signs in. Changing the address at the provider
  afterwards changes nothing here.
- The first sign-in finds the account by **email address** — and only if the provider says it has
  verified that address (`email_verified: true`). See `OIDC_REQUIRE_VERIFIED_EMAIL` below.
- With `OIDC_AUTO_CREATE=true`, somebody the provider lets in and plMail has never seen gets a new,
  ordinary (non-admin) account, named from the provider's `given_name`/`family_name`. Without it, an
  administrator creates the account first under **Admin → Users**, with the same address.
- Everything that applies to a password sign-in applies here: a suspended account is refused, the
  login throttle counts attempts, and an account with two-factor switched on is asked for its code.

## Setting it up in Authentik

1. **Applications → Providers → Create → OAuth2/OpenID Provider.**
   - *Client type*: **Confidential**.
   - *Redirect URIs*: **Strict**, `https://<your plMail address>/login/oidc/callback` — the address
     people type to reach plMail, the one in `APP_PUBLIC_URL`.
   - *Scopes*: leave the default `openid`, `email` and `profile` mappings selected.
   - Anything else can stay at its default.
2. **Applications → Applications → Create**, pick the provider you just made, and give it a slug —
   `plmail`, say. Bind a group or policy to it if not everybody in Authentik should get in; Authentik
   then refuses the others before they ever reach plMail.
3. From the provider's page, copy the **Client ID**, the **Client Secret** and the **OpenID
   Configuration Issuer** — something like `https://auth.example.com/application/o/plmail/`.
4. Set the variables on every plMail container — `compose.yaml` passes them through from your
   environment — and restart:

   ```bash
   OIDC_ISSUER=https://auth.example.com/application/o/plmail/
   OIDC_CLIENT_ID=…
   OIDC_CLIENT_SECRET=…
   OIDC_BUTTON_LABEL=Authentik
   ```

Keycloak and the rest are the same four facts under different names: a confidential client, the
redirect URI above, and the realm's issuer URL.

## The variables

| Variable | What it does | Default |
|---|---|---|
| `OIDC_ISSUER` | The provider's issuer URL, exactly as its discovery document states it. Must be `https://`. | blank (off) |
| `OIDC_CLIENT_ID` | The client id the provider issued. | blank (off) |
| `OIDC_CLIENT_SECRET` | The client secret. | blank (off) |
| `OIDC_BUTTON_LABEL` | The provider's name on the button — "Sign in with Authentik". Blank says "single sign-on". | blank |
| `OIDC_SCOPES` | Space-separated scopes. `openid` is always added. | `openid email profile` |
| `OIDC_AUTO_CREATE` | Create an account for somebody plMail has never seen. | `false` |
| `OIDC_REQUIRE_VERIFIED_EMAIL` | Link an existing account by address only when the provider vouches for the address. | `true` |

Single sign-on is off unless all three of the first three are set.

## Things that bite

**"Your sign-in provider has not confirmed your email address."** Authentik's default `email` scope
mapping has not always said `email_verified: true`, depending on the version. Either give the
provider a scope mapping of your own that returns `"email_verified": True` for addresses your
administrators set, or — if people cannot edit their own address in Authentik — set
`OIDC_REQUIRE_VERIFIED_EMAIL=false`. Do not turn it off on a provider where anybody can change their
own address: they could then claim any plMail account that has not signed in through the provider
yet, administrators included.

**The provider says the redirect URI does not match.** plMail builds the callback address from the
request it is serving. Behind a reverse proxy that does not pass `X-Forwarded-Proto`, or with
`TRUSTED_PROXIES` too narrow to believe it, that address starts with `http://` and the provider
refuses it. See [Behind a reverse proxy](../install/reverse-proxy.md).

**The issuer has to be `https://`.** The ID token is trusted because it arrives over TLS directly from
the provider's token endpoint, so a provider on plain HTTP could be impersonated by anybody on the
path. plMail refuses it and the button reports single sign-on as unavailable; the log says why.

**Signing out of plMail does not sign you out of the provider.** Pressing the button again signs
you straight back in without a prompt, because the provider still remembers you.

**Two-factor is asked twice** if an account has it switched on here as well as at the provider.
Switch it off under **Settings → Security** if the provider's is enough.

**An account created by the provider has no password.** It signs in through the provider only, and
app passwords for JMAP and CalDAV clients work as for anybody. An administrator gives it a password
with `bin/console app:user:password` if one is wanted.

**Switching to a different provider relinks by address.** The link remembers which issuer it was
made with, so a new issuer never matches an old subject; each person's next sign-in links their
account again by its (verified) address. A [configuration backup](../install/config-backup.md) does
not carry the links either, and they come back the same way.

**Discovery is cached for an hour.** A provider whose endpoints changed is picked up within the hour,
or at once after `bin/console cache:pool:clear cache.app`.
