# Storage

Vigie writes activities, it never reads them back. `ActivityStorageInterface` has a single method,
`store(Activity $activity): void`. `iq2i_vigie.storage` selects the implementation: `monolog` (the
default), `in_memory`, or a service id of your own (see [Writing your own storage](#writing-your-own-storage)
below).

## Choosing a storage

`monolog` (the default) writes each activity as one NDJSON line, formatted as an ECS (Elastic Common
Schema) document, through a dedicated `vigie.activity` channel. See
[The default Monolog storage](#the-default-monolog-storage) below.

`in_memory` is a test double, not a production option. See [doc/testing.md](testing.md).

## The default Monolog storage

`output.path`/`output.handlers` configure it, see [doc/configuration.md](configuration.md).

With `output.handlers` left empty, Vigie registers a single `Monolog\Handler\StreamHandler` writing to
`output.path`, formatted by its own `EcsFormatter` (service id `iq2i_vigie.formatter.ecs`). This handler
is attached to a `Monolog\Logger` on the `vigie.activity` channel, a channel not declared to
`symfony/monolog-bundle`.

One line looks like:

```json
{"@timestamp":"2026-08-27T09:12:33.481920+00:00","message":"http_request POST /admin/orders/42 jane.doe from 10.0.0.0","ecs":{"version":"8.11.0"},"event":{"kind":"event","category":["web"],"type":["access"],"outcome":"success","action":"http_request","id":"01926f5e-...","created":"2026-08-27T09:12:33.512300+00:00","dataset":"vigie.activity"},"service":{"name":"shop","environment":"prod"},"user":{"name":"jane.doe"},"user_agent":{"original":"curl/8"},"source":{"address":"10.0.0.0","ip":"10.0.0.0"},"http":{"request":{"method":"POST"},"response":{"status_code":200}},"url":{"path":"/admin/orders/42"},"related":{"user":["jane.doe"],"ip":["10.0.0.0"]},"vigie":{"type":"http_request","route":"admin_order_edit","firewall":"main","session_id":"…"}}
```

This is a stable contract, not just a convenient dump. See the published
[JSON Schema](schema/activity.json) (`ecs.version` in each line). Query a specific event across a
file rotation with `jq`:

```bash
jq 'select(.vigie.route == "admin_order_edit")' var/log/vigie.jsonl
```

For the full field-by-field mapping from an `Activity` to its ECS document, see [doc/siem.md](siem.md).

Vigie does not rotate this file itself. Hand it to `logrotate` like any other log file:

```
/path/to/var/log/vigie.jsonl {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

For a containerized deployment that ships its activity log the way it already ships every other line the
process prints, point a handler at `php://stdout`:

```yaml
# config/services.yaml
services:
    app.vigie.stdout_handler:
        class: Monolog\Handler\StreamHandler
        arguments: ['php://stdout']
        calls:
            - setFormatter: ['@iq2i_vigie.formatter.ecs']
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    output:
        handlers: ['app.vigie.stdout_handler']
```

Once `output.handlers` is set, Vigie never touches a listed handler's formatter. Set it yourself, as
above, or through `monolog.yaml` (`formatter: 'iq2i_vigie.formatter.ecs'`) if the handler is declared
there instead. Any number of handlers can be listed: each one receives every activity.

Redaction stays global. `record.*` runs once, before an activity is turned into a document; there is
no per-handler redaction. Turning `record.ip_address` on so one handler gets a usable IP means every
other configured handler gets the raw IP too.

## Sending to syslog

`output.syslog` adds a syslog handler **on top of** the file handler (or whichever `output.handlers` you
listed), so the NDJSON file is always written and syslog is optional. Useful for a fleet of load-balanced
servers feeding one central collector without a log-shipping agent installed on every node; see
[doc/multi-server.md](multi-server.md) for the two topologies, when to prefer one over the other, and the
CrowdSec acquisition side.

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    output:
        syslog:
            enabled: '%env(bool:VIGIE_SYSLOG_ENABLED)%'
            host: '%env(VIGIE_SYSLOG_HOST)%'   # omit to write to the machine's own syslog instead
            port: 514
            facility: local0
            ident: vigie
            max_length: 8192
```

- `enabled` accepts an env placeholder and is read at runtime, so one build ships everywhere and syslog
  is switched on per environment. While it is off, no socket is opened and `ext-sockets` is not needed.
- With a `host`, Vigie sends RFC 5424 datagrams over UDP (`Monolog\Handler\SyslogUdpHandler`, needs the
  `sockets` PHP extension, checked when the first activity is recorded). Without one, it writes through
  `syslog(3)` (`SyslogHandler`) for a local rsyslog to relay.
- The document is formatted by `iq2i_vigie.formatter.ecs.syslog`: the same line without the trailing
  `"\n"`, which rsyslog would otherwise escape as a literal `#012` glued to the JSON.
- `max_length` is the largest datagram sent, header included. A line is roughly 1.5 KB and grows with
  `context`; keep it above that and not above the collector's own limit (CrowdSec's `max_message_len`). A
  datagram past it is truncated, and a truncated line is no longer valid JSON.

UDP is fire-and-forget: with the collector down, the request still answers normally and the file is still
written.

Prefer declaring the handler yourself when you need something `output.syslog` does not cover (TCP, a
different RFC): `output.handlers` still takes any Monolog handler, with `iq2i_vigie.formatter.ecs.syslog`
as its formatter.

## Writing your own storage

```php
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;

final class RedisActivityStorage implements ActivityStorageInterface
{
    public function store(Activity $activity): void { /* ... */ }
}
```

```yaml
# config/packages/vigie.yaml
iq2i_vigie:
    storage: App\Vigie\Storage\RedisActivityStorage
```

`app`/`env`/`hostname` are stamped onto the ECS document by the built-in Monolog storage, not carried on
`Activity` itself. A storage of your own doesn't receive them and is free to tag its own records however
it sees fit.

## Threat decision storage

A separate concern, unrelated to the storage above. See [doc/threat.md](threat.md).
