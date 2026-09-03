# Storage

Vigie writes activities, it never reads them back — `ActivityStorageInterface` has a single method,
`store(Activity $activity): void`. `iq2i_vigie.storage` selects the implementation: `monolog` (the
default), `in_memory`, or a service id of your own (see [Writing your own storage](#writing-your-own-storage)
below).

## Choosing a storage

**Monolog** (`storage: monolog`, the default) writes each activity as one NDJSON line, formatted as an
ECS (Elastic Common Schema) document, through a dedicated `vigie.activity` channel — see
[The default Monolog storage](#the-default-monolog-storage) below.

**In-memory** (`storage: in_memory`) is a test double, not a production option — see
[doc/testing.md](testing.md).

## The default Monolog storage

`output.path`/`output.handlers` configure it — see [doc/configuration.md](configuration.md).

With `output.handlers` left empty, Vigie registers a single `Monolog\Handler\StreamHandler` writing to
`output.path`, formatted by its own `EcsFormatter` (service id `iq2i_vigie.formatter.ecs`). This handler
is attached to a `Monolog\Logger` on the `vigie.activity` channel — a channel not declared to
`symfony/monolog-bundle`.

One line looks like:

```json
{"@timestamp":"2026-08-27T09:12:33.481920+00:00","message":"http_request POST /admin/orders/42 jane.doe from 10.0.0.0","ecs":{"version":"8.11.0"},"event":{"kind":"event","category":["web"],"type":["access"],"outcome":"success","action":"http_request","id":"01926f5e-...","created":"2026-08-27T09:12:33.512300+00:00","dataset":"vigie.activity"},"service":{"name":"shop","environment":"prod"},"user":{"name":"jane.doe"},"user_agent":{"original":"curl/8"},"source":{"address":"10.0.0.0","ip":"10.0.0.0"},"http":{"request":{"method":"POST"},"response":{"status_code":200}},"url":{"path":"/admin/orders/42"},"related":{"user":["jane.doe"],"ip":["10.0.0.0"]},"vigie":{"type":"http_request","route":"admin_order_edit","firewall":"main","session_id":"…"}}
```

This is a versioned contract, not just a convenient dump — see the published
[JSON Schema](schema/activity-2.0.json) (`ecs.version` in each line). Query a specific event across a
file rotation with `jq`:

```bash
jq 'select(.vigie.route == "admin_order_edit")' var/log/vigie.jsonl
```

For the full field-by-field mapping from an `Activity` to its ECS document, see [doc/siem.md](siem.md).

**Vigie never rotates this file itself.** Hand it to `logrotate` like any other log file:

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

Once `output.handlers` is set, Vigie never touches a listed handler's formatter — set it yourself, as
above, or through `monolog.yaml` (`formatter: 'iq2i_vigie.formatter.ecs'`) if the handler is declared
there instead. Any number of handlers can be listed: each one receives every activity.

**Redaction stays global.** `record.*` runs once, before an activity is turned into a document; there is
no per-handler redaction. Concretely: turning `record.ip_address` on so one handler gets a usable IP means
every other configured handler gets the raw IP too.

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

## Threat decision storage

A separate concern, unrelated to the storage above — see [doc/threat.md](threat.md).
