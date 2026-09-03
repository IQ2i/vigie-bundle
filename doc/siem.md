# Consuming the ECS output

Vigie's own output is the acquisition source: point a log shipper or a SIEM's agent at the NDJSON file (or
stream) configured under `iq2i_vigie.output` — see [doc/storage.md](storage.md) for how that file is
written and rotated. This page covers the other end: reading it.

## Field mapping

Every line is one ECS (Elastic Common Schema) document, `ecs.version` `8.11.0`, `event.dataset`
`vigie.activity`, `event.kind` `event`. From an `Activity` (see [doc/recording.md](recording.md)):

- `occurredAt` → `@timestamp` (RFC 3339, microseconds, UTC)
- `recordedAt` (when the line was actually written) → `event.created`
- `eventId` → `event.id`
- `app` / `env` → `service.name` / `service.environment`
- `type` → `vigie.type`, plus `event.category` / `event.type` / `event.outcome` — see below
- `action` → `event.action`
- `userIdentifier` → `user.name` (recorded in the clear) or `user.hash` (`record.user_identifier: hash`);
  either way, also into `related.user`
- `ipAddress` → `source.address` always; `source.ip` only when it validates as an IP address (a raw or
  anonymized value does, a hashed one doesn't); also into `related.ip` when valid
- `userAgent` → `user_agent.original`
- `method` → `http.request.method`
- `uri` → `url.path`, and `url.query` when `record.query_string` kept a `?` in the recorded uri
- `statusCode` → `http.response.status_code`
- `requestId` → `http.request.id`
- `route` / `firewall` / `sessionId` → `vigie.route` / `vigie.firewall` / `vigie.session_id` (always an
  HMAC)
- `subject` → `vigie.subject.type` / `vigie.subject.id`
- `context` → `vigie.context` (an object, scalars only)
- `context.impersonator` / `context.original_user` → additionally copied into `user.effective.name` and
  `related.user`

A field an activity has no value for is omitted, never emitted as `null`. The full contract, including
which fields are always present, is the published [JSON Schema](schema/activity-2.0.json).

## `event.category` / `event.type` / `event.outcome`

One fixed mapping per `ActivityType`:

- `http_request` → `[web]` / `[access]` / `success` when the status code is below 400, `failure` otherwise
- `login_success` → `[authentication]` / `[start]` / `success`
- `login_failure` → `[authentication]` / `[start]` / `failure` (`[start, denied]` when `context.throttled`)
- `logout` → `[authentication]` / `[end]` / `success`
- `switch_user` → `[authentication, iam]` / `[start]` (entering impersonation) or `[end]` (exiting, from
  `context.direction`) / `success`
- `token_deauthenticated` → `[authentication]` / `[end]` / `failure`
- `access_denied` → `[authentication]` / `[denied]` / `failure`
- `password_changed`, `roles_changed` → `[iam]` / `[user, change]` / `success`
- `csrf_failure` → `[web]` / `[denied]` / `failure`
- `custom` → `[]` / `[info]` / no `outcome`

## CrowdSec acquisition

```yaml
# /etc/crowdsec/acquis.d/vigie.yaml
filenames:
  - /path/to/var/log/vigie.jsonl
labels:
  type: vigie_ecs
```

CrowdSec needs a parser translating the fields above into its own `evt.Parsed`/`evt.Meta`, since it has no
built-in ECS support. A minimal one, extracting what a source-ip-based scenario needs:

```yaml
# /etc/crowdsec/parsers/s01-parse/vigie-ecs.yaml
filter: "evt.Line.Labels.type == 'vigie_ecs'"
onsuccess: next_stage
name: local/vigie-ecs
description: "Parse Vigie's ECS output"
statics:
  - parsed: source_ip
    expression: JsonExtract(evt.Line.Raw, "source.ip")
  - parsed: http_path
    expression: JsonExtract(evt.Line.Raw, "url.path")
  - parsed: http_status
    expression: JsonExtract(evt.Line.Raw, "http.response.status_code")
  - meta: log_type
    value: http_access-log
  - target: evt.StrTime
    expression: JsonExtract(evt.Line.Raw, "@timestamp")
```

Adjust `statics` to whatever the scenarios actually running need (`vigie.subject.id` for a business-level
ban, `user.name` for an account-takeover scenario). See
[The pseudonymization pitfall](threat.md#the-pseudonymization-pitfall) before relying on `source.ip` for a
scenario: it's only populated when `record.ip_address` isn't `anonymize`.

## Elastic ingestion

Filebeat's `ndjson` parser reads an already-ECS-shaped line directly into top-level fields, with nothing
else to configure:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: filestream
    id: vigie
    paths:
      - /path/to/var/log/vigie.jsonl
    parsers:
      - ndjson:
          keys_under_root: true
          overwrite_keys: true
          add_error_key: true

output.elasticsearch:
  hosts: ['https://localhost:9200']
```

## Wazuh ingestion

```xml
<!-- ossec.conf -->
<localfile>
    <log_format>json</log_format>
    <location>/path/to/var/log/vigie.jsonl</location>
</localfile>
```

Wazuh indexes the JSON object verbatim; build rules and decoders against the `vigie.*`/`event.*`/`source.*`
fields the same way as any other JSON source.
