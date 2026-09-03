# Vigie Bundle

Emits who did what, when and from where in your Symfony application: an opt-in, GDPR-aware activity log,
written as ECS (Elastic Common Schema) NDJSON for a SIEM to consume — never queried back from the
application itself.

- Records HTTP requests (opt-in), security events (login, logout, switch user) and your own business
  events, as a stream of `Activity` objects, immediately written out — see [doc/recording.md](doc/recording.md).
- Reads back the decisions a SIEM (CrowdSec today) makes about suspicious IPs, ranges, sessions, users,
  countries and AS numbers, through `ThreatCheckerInterface`, an opt-in enforcement listener, and a signed
  push endpoint for a SIEM that can't be polled — the return path for whatever consumed the activity stream
  above. Nothing here is on unless you turn it on; see [doc/threat.md](doc/threat.md).
- Ships no HTML dashboard, no read API, and no entity-change auditing — the ECS output is the interface; see
  [doc/siem.md](doc/siem.md) for consuming it, or
  [damienharper/auditor-bundle](https://github.com/DamienHarper/auditor-bundle) for entity diffs.
- Requires PHP 8.3+ and Symfony 6.4/7.4/8.x. No database: activities are written through Monolog to a plain
  NDJSON file (the default) or a stdout stream for containers.

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

That's it — activities start flowing to `%kernel.logs_dir%/vigie.jsonl` as ECS documents. See
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

See [doc/recording.md](doc/recording.md) for the rest: processors, the `Subject`, vetoing a recording.

## Documentation

- [doc/recording.md](doc/recording.md) — the `Activity` model, what's recorded automatically, your own
  activities, processors
- [doc/storage.md](doc/storage.md) — the default Monolog/ECS storage, writing to stdout or a custom
  handler, writing your own storage
- [doc/siem.md](doc/siem.md) — the ECS field mapping, CrowdSec acquisition, Elastic/Wazuh ingestion
- [doc/threat.md](doc/threat.md) — reading back a SIEM's decisions, `ThreatCheckerInterface`, opt-in
  enforcement, the signed push endpoint, `vigie:threat:sync`/`vigie:threat:list`, the CrowdSec provider,
  writing your own
- [doc/remediation.md](doc/remediation.md) — recipes reacting to a decision: revoking a session, locking an
  account, disabling it, notifying
- [doc/configuration.md](doc/configuration.md) — full `iq2i_vigie.*` reference, optional dependencies
- [doc/testing.md](doc/testing.md) — testing your own code against vigie, without a database
- [doc/recipes.md](doc/recipes.md) — listeners for scheb/2fa, symfony/login-link, symfonycasts/reset-password

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
