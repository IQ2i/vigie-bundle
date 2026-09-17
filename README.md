# Vigie Bundle

Know who did what, when and from where in your Symfony application: a structured, queryable activity log,
written as ECS (Elastic Common Schema) NDJSON, with zero database. Install it on its own to get an
activity log an admin backend or a support team can grep, `jq`, or ship to Elastic. The application never
queries it back itself.

And if you want to act on it: plug a SIEM behind the same stream and it becomes a detection/response
loop, reading decisions back into the application. See [Two ways to use Vigie](#two-ways-to-use-vigie).

- Records HTTP requests (opt-in), security events (login, logout, switch user) and your own business
  events, as a stream of `Activity` objects, immediately written out. See [doc/recording.md](doc/recording.md).
- No database: activities are written through Monolog to a plain NDJSON file (the default), a stdout
  stream for containers, or syslog for a load-balanced fleet. See [doc/multi-server.md](doc/multi-server.md).
- Anonymizes IPs (`record.ip_address: anonymize`) and always HMACs session ids by default; user
  identifiers are recorded in the clear by default, and `record.user_identifier: hash` replaces them with
  a stable, non-reversible pseudonym (`user.hash`) instead. Privacy-preserving defaults, not a compliance
  claim: Vigie does not make an application GDPR-compliant on its own. See
  [doc/configuration.md](doc/configuration.md).
- Optionally reads back the decisions a SIEM makes about suspicious IPs, ranges, sessions, users,
  countries and AS numbers, through `ThreatCheckerInterface`, an opt-in enforcement listener, and a signed
  push endpoint for a SIEM that can't be polled. Nothing here is on unless you turn it on; see
  [doc/threat.md](doc/threat.md).
- Ships no HTML dashboard, no read API, and no entity-change auditing. The ECS output is the interface; see
  [doc/siem.md](doc/siem.md) for consuming it, or
  [damienharper/auditor-bundle](https://github.com/DamienHarper/auditor-bundle) for entity diffs.
- Requires PHP 8.3+ and Symfony 6.4/7.4/8.x.

## Quickstart

```bash
composer require iq2i/vigie-bundle
```

```php
// config/bundles.php
return [
    // ...
    IQ2i\VigieBundle\IQ2iVigieBundle::class => ['all' => true],
];
```

Activities start flowing to `%kernel.logs_dir%/vigie.jsonl` as ECS documents. See
[doc/storage.md](doc/storage.md) to point it at stdout or a custom Monolog handler instead.

Security events (login, logout, switch user) are recorded automatically. Opt an HTTP controller in with
`#[Track]`:

```php
use IQ2i\VigieBundle\Attribute as Vigie;

#[Vigie\Track] // opts every action of this controller into recording
class AdminDashboardController
{
    // ...
}
```

Record a business event in one line:

```php
$this->recorder->custom('export.completed', ['rows' => 42]); // ActivityRecorderInterface
```

See [doc/recording.md](doc/recording.md) for processors, the `Subject`, and vetoing a recording.

## Two ways to use Vigie

**(a) Activity log only.** Install the bundle, opt controllers in with `#[Track]`, record your own
events with `custom()`, and read `vigie.jsonl` with `jq`, tail it, or ship it to Elastic/Wazuh — see
[doc/siem.md](doc/siem.md). This requires nothing from `threat.*`: no SIEM, no LAPI, no enforcement
listener. A structured activity log is the whole deliverable.

**(b) The full loop, with a SIEM.** Point CrowdSec (or another SIEM) at the same `vigie.jsonl`, let a
scenario reason over it, and read decisions back into the application through
`ThreatCheckerInterface` — see [doc/threat.md](doc/threat.md) and [crowdsec/](crowdsec). Opt-in,
layered entirely on top of (a): nothing about the activity log changes when this is off.

## Documentation

- [doc/recording.md](doc/recording.md): the `Activity` model, what's recorded automatically, your own
  activities, processors
- [doc/storage.md](doc/storage.md): the default Monolog/ECS storage, writing to stdout, syslog or a custom
  handler, writing your own storage
- [doc/siem.md](doc/siem.md): the ECS field mapping, CrowdSec acquisition, Elastic/Wazuh ingestion
- [crowdsec/](crowdsec): a CrowdSec parser and six ready-to-install scenarios reading Vigie's own output
  directly (login brute force, credential stuffing, access-denied probing, CSRF wave, impersonation abuse,
  IDOR probing)
- [doc/multi-server.md](doc/multi-server.md): a load-balanced fleet, correlating a visitor across nodes,
  telling nodes apart, shipping straight to syslog
- [doc/multi-tenant.md](doc/multi-tenant.md): one CrowdSec instance shared across several client
  applications, one bouncer key per app, the cross-tenant leak on `username`/`session` scopes
- [doc/threat.md](doc/threat.md): reading back a SIEM's decisions, `ThreatCheckerInterface`, opt-in
  enforcement, the signed push endpoint, `vigie:threat:sync`/`vigie:threat:list`, the CrowdSec provider,
  writing your own
- [doc/remediation.md](doc/remediation.md): recipes reacting to a decision, revoking a session, locking an
  account, disabling it, notifying
- [doc/configuration.md](doc/configuration.md): full `iq2i_vigie.*` reference, optional dependencies
- [doc/testing.md](doc/testing.md): testing your own code against vigie, without a database
- [doc/recipes.md](doc/recipes.md): listeners for scheb/2fa, symfony/login-link, symfonycasts/reset-password

## Why not the official CrowdSec bouncer?

[`crowdsecurity/bouncer-lib`](https://github.com/crowdsecurity/php-cs-bouncer) and its Symfony bundle already
poll or stream the LAPI, cache decisions, and remediate — the same job `ThreatCheckerInterface` and
`ThreatEnforcementSubscriber` do here. Three things they don't do, which is what Vigie is actually for:

- **The other direction.** A bouncer only ever reads decisions back. Vigie is first an emitter: the
  ECS stream a scenario reasons over (`login_failure` with the identifier that failed, `switch_user`,
  `access_denied`) doesn't exist without it, whatever reads decisions back.
- **`session`/`username` scopes.** A network bouncer sits in front of the app and only ever sees an IP; it
  has no way to revoke a session or lock an account by identifier, the scopes CrowdSec itself supports but
  a reverse-proxy bouncer can't act on. See [doc/remediation.md](doc/remediation.md).
- **Multi-SIEM.** `ThreatProviderInterface` and the signed push endpoint (`threat.ingest`) mean CrowdSec is
  one provider among others (Wazuh, a Sentinel playbook, any SOAR), not the only thing this reads decisions
  from.

If the only need is banning IPs at the edge, the official bouncer or the reverse proxy is the better fit,
and cheaper: no PHP request pays for a lookup that already happened upstream. Vigie's enforcement exists for
the scopes that layer can't see, and for a deployment with no such layer at all.

## Versioning and security

Classes marked `@internal` and `final` are implementation details and are not covered by
semver; everything else is.

Please **do not** open a public GitHub issue for a suspected security vulnerability. Instead, report it
privately by emailing loic@sapone.fr with a description, steps to reproduce, and the affected commit.
You should get an initial response within a few business days.

## Sponsors

<p align="center">
  <a target="_blank" href="https://www.mezcalito.fr">
    <img alt="Mezcalito - Agence Digitale à Grenoble depuis 2006" src="https://raw.githubusercontent.com/IQ2i/vigie-bundle/main/doc/static/mezcalito.svg" width="300">
  </a>
</p>
