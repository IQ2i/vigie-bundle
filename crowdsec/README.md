# CrowdSec collection for Vigie

A parser and six scenarios reading Vigie's ECS activity stream (`vigie.jsonl`, see
[doc/storage.md](../doc/storage.md)) directly, without going through a web server's access log. Not
published to the CrowdSec Hub yet: install by copying these files onto the CrowdSec host.

## Before installing: things that silently make a scenario a no-op

- **A profile routing `username`-scoped alerts.** `vigie-access-denied-probing`, `vigie-impersonation-abuse`
  and `vigie-idor-probing` group by a user identifier and declare `scope: {type: username, ...}`, but a
  scenario's `scope` directive only sets what the *alert* carries — the LAPI's **profiles** decide what
  the resulting *decision* looks like, and the default profile shipped with CrowdSec only matches
  `Alert.GetScope() == "Ip"`. **Without [profiles/vigie.yaml](profiles/vigie.yaml) installed, these three
  scenarios still produce nothing but `Ip`-scoped decisions**, silently reintroducing the raw-IP
  requirement the user-keyed grouping was meant to avoid, and never the `username` decisions
  `ThreatCheckerInterface` and [doc/remediation.md](../doc/remediation.md) are built around.
- **`iq2i_vigie.threat.crowdsec.scopes` must list `username`.** The built-in CrowdSec provider only
  requests the scopes it's configured with from the LAPI stream (`['Ip', 'Range']` by default, see
  [doc/configuration.md](../doc/configuration.md)); even with the profile above installed and the
  scenario firing correctly, `vigie:threat:sync` never downloads a `username` decision it wasn't asked
  for.
- **`record.ip_address: true`, but only for the IP-keyed scenarios.** `vigie-login-bruteforce`,
  `vigie-credential-stuffing` and `vigie-csrf-wave` ban by `source_ip`. Vigie's default,
  `record.ip_address: anonymize`, masks the host part (`1.2.3.4` → `1.2.3.0`), so these three scenarios
  fed that output only ever see a `/24`/`/64` and never match a real address again. See
  [The pseudonymization pitfall](../doc/threat.md#the-pseudonymization-pitfall). This trades away IP
  anonymization in whatever storage receives this same output; run two pipelines (see
  [doc/storage.md](../doc/storage.md#writing-your-own-storage)) if you need the raw IP for CrowdSec
  and an anonymized one elsewhere. The three user-keyed scenarios above don't need this at all.
- **`vigie.remediation`.** Every scenario's `filter` excludes lines carrying it
  (`evt.Meta.remediation == ''`): a request Vigie's own `ThreatEnforcementSubscriber` already blocked
  (see [doc/threat.md](../doc/threat.md#enforcing-a-decision)) must never re-feed the scenario that
  produced the ban in the first place, or the decision keeps re-triggering itself. Don't remove this
  clause when adapting a scenario.

`vigie-idor-probing.yaml` additionally needs the application to populate `Subject::$owner` on the
resources it records access to; see [doc/recording.md](../doc/recording.md#subject). Without it,
`vigie.subject.owner` is never present and the scenario never fires.

## Installing

```bash
# On the CrowdSec host:
cp acquis/vigie.yaml.example /etc/crowdsec/acquis.d/vigie.yaml   # edit the path to your vigie.jsonl
cp parsers/s01-parse/vigie-ecs.yaml /etc/crowdsec/parsers/s01-parse/
cp scenarios/*.yaml /etc/crowdsec/scenarios/
cp collections/vigie.yaml /etc/crowdsec/collections/

# profiles/vigie.yaml isn't a drop-in file: prepend it to the existing /etc/crowdsec/profiles.yaml,
# before the profile matching Alert.GetScope() == "Ip" — see profiles/vigie.yaml for why the order matters.

systemctl reload crowdsec
cscli parsers list      # local/vigie-ecs should show up
cscli scenarios list    # the six local/vigie-* scenarios should show up
```

Then add `username` to `iq2i_vigie.threat.crowdsec.scopes` (default `['Ip', 'Range']`) so
`vigie:threat:sync` actually pulls the decisions the profile above now produces:

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    threat:
        crowdsec:
            scopes: ['Ip', 'Range', 'username']
```

For a load-balanced fleet shipping to syslog instead of one file per node, see
[doc/multi-server.md](../doc/multi-server.md#sending-to-syslog) and adjust `acquis/vigie.yaml.example`
accordingly (a `type: syslog` datasource instead of `filenames`); the parser's `filter` still matches on
`evt.Line.Labels.type`, set by whichever acquisition method is used.

For one CrowdSec instance shared across several client applications instead of one application's own
fleet, see [doc/multi-tenant.md](../doc/multi-tenant.md): the scenarios here need adapting before that's
safe, since a `username`/`session` decision isn't namespaced by application as shipped.

## What's here

- `parsers/s01-parse/vigie-ecs.yaml`: maps the ECS document's fields into `evt.Meta.*`
  (`vigie_type`, `tenant` (`service.name`, see [doc/multi-tenant.md](../doc/multi-tenant.md)),
  `source_ip`, `http_path`, `http_status`, `route`, `firewall`, `user_name`, `user_hash`,
  `user_identifier` — whichever of the previous two is populated, `user_effective_name`,
  `subject_type`, `subject_id`, `subject_owner`, `remediation`, `event_outcome`). See
  [doc/siem.md](../doc/siem.md) for the full field-by-field mapping this parser draws from.
- `scenarios/vigie-login-bruteforce.yaml`: repeated `login_failure` against one account from one IP.
- `scenarios/vigie-credential-stuffing.yaml`: many distinct usernames failing from the same IP.
- `scenarios/vigie-access-denied-probing.yaml`: a burst of `access_denied` from one authenticated user,
  `username`-scoped.
- `scenarios/vigie-csrf-wave.yaml`: a wave of `csrf_failure` from one IP.
- `scenarios/vigie-impersonation-abuse.yaml`: an abnormal rate of `switch_user` by one admin,
  `username`-scoped.
- `scenarios/vigie-idor-probing.yaml`: repeated access to a resource `Subject::$owner` says isn't the
  caller's, grouped and `username`-scoped by the acting user (not by IP, so an attacker rotating IPs on
  one account is still caught).
- `profiles/vigie.yaml`: an example LAPI profile routing the three `username`-scoped scenarios above to
  a `username`-scoped decision instead of the LAPI's default `Ip` one. See
  [Before installing](#before-installing-things-that-silently-make-a-scenario-a-no-op) above.

`tests/CrowdSec/CollectionTest.php` (in the main test suite) checks every `JsonExtract` path in the
parser against [doc/schema/activity.json](../doc/schema/activity.json) and every `vigie.type`/scenario
label against `ActivityType`, so a schema change that silently breaks this collection fails CI instead
of failing quietly in production.

## Tuning

`capacity`/`leakspeed`/`blackhole` are starting points, not measured against real traffic. A public app
with heavier legitimate failed-login volume than an admin backend will want a looser
`vigie-login-bruteforce`; an internal tool with none at all can tighten it. See CrowdSec's own
documentation on leaky buckets for what each key controls.
