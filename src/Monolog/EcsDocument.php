<?php

declare(strict_types=1);

/*
 * This file is part of the Vigie Bundle.
 *
 * (c) Loïc Sapone <loic@sapone.fr>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace IQ2i\VigieBundle\Monolog;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;

/**
 * The pure `Activity → ECS document` mapping, reused by EcsFormatter (via
 * MonologActivityStorage) and by EcsSchemaTest.
 *
 * @internal
 *
 * @phpstan-type EcsEvent array{kind: string, category: list<string>, type: list<string>, outcome?: string, action: string, id: string, created: string, dataset: string}
 * @phpstan-type EcsUser array{name?: string, hash?: string, effective?: array{name: string}}
 * @phpstan-type EcsSource array{address: string, ip?: string}
 * @phpstan-type EcsHttp array{request?: array{method?: string, id?: string}, response?: array{status_code: int}}
 * @phpstan-type EcsUrl array{path: string, query?: string}
 * @phpstan-type EcsRelated array{user?: list<string>, ip?: list<string>}
 * @phpstan-type EcsSubject array{type: string, id: string}
 * @phpstan-type EcsVigie array{type: string, route?: string, firewall?: string, session_id?: string, subject?: EcsSubject, context?: object, remediation?: string}
 * @phpstan-type EcsDocumentShape array{'@timestamp': string, ecs: array{version: string}, event: EcsEvent, service?: array{name?: string, environment?: string}, user?: EcsUser, user_agent?: array{original: string}, source?: EcsSource, http?: EcsHttp, url?: EcsUrl, related?: EcsRelated, vigie: EcsVigie}
 */
final class EcsDocument
{
    // ECS version stamped on every document — see doc/schema/activity-2.0.json.
    public const ECS_VERSION = '8.11.0';

    // RFC 3339 with microseconds, forced to UTC — DateTimeInterface::ATOM
    // would drop them, and a sort on @timestamp would lose sub-second
    // precision for nothing.
    private const DATE_FORMAT = 'Y-m-d\TH:i:s.uP';

    // A hash produced by Pseudonymizer::hash() (hash_hmac('sha256', ...)) is always exactly this shape —
    // tells "already pseudonymized" apart from "kept in the clear" without threading record.* through here.
    private const HASH_PATTERN = '/^[0-9a-f]{64}$/';

    private function __construct()
    {
    }

    /**
     * @return EcsDocumentShape
     */
    public static function fromActivity(Activity $activity, \DateTimeImmutable $recordedAt, ?string $app = null, ?string $env = null): array
    {
        /** @var EcsDocumentShape $document */
        $document = [
            '@timestamp' => self::formatDate($activity->occurredAt),
            'ecs' => ['version' => self::ECS_VERSION],
            'event' => self::event($activity, $recordedAt),
            'vigie' => self::vigie($activity),
        ];

        $service = [];
        if (null !== $app) {
            $service['name'] = $app;
        }
        if (null !== $env) {
            $service['environment'] = $env;
        }
        if ([] !== $service) {
            $document['service'] = $service;
        }

        $user = self::user($activity);
        if ([] !== $user) {
            $document['user'] = $user;
        }

        if (null !== $activity->userAgent) {
            $document['user_agent'] = ['original' => $activity->userAgent];
        }

        $source = self::source($activity);
        if ([] !== $source) {
            $document['source'] = $source;
        }

        $http = self::http($activity);
        if ([] !== $http) {
            $document['http'] = $http;
        }

        $url = self::url($activity);
        if ([] !== $url) {
            $document['url'] = $url;
        }

        $related = self::related($activity);
        if ([] !== $related) {
            $document['related'] = $related;
        }

        return $document;
    }

    /**
     * A short, human-readable summary — "login_failure jane.doe from 203.0.113.0" — never the record of
     * truth, just what a human skimming logs or a Kibana Discover row sees at a glance.
     */
    public static function message(Activity $activity): string
    {
        $parts = [$activity->type->value];

        if (ActivityType::Custom === $activity->type) {
            $parts = [$activity->action ?? $activity->type->value];
        } elseif (ActivityType::HttpRequest === $activity->type) {
            $parts[] = trim(\sprintf('%s %s %s', $activity->method ?? '', $activity->uri ?? '', (string) ($activity->statusCode ?? '')));
        }

        if (null !== $activity->userIdentifier) {
            $parts[] = $activity->userIdentifier;
        }

        if (null !== $activity->ipAddress) {
            $parts[] = 'from '.$activity->ipAddress;
        }

        return implode(' ', array_filter($parts, static fn (string $part): bool => '' !== $part));
    }

    /**
     * @return EcsEvent
     */
    private static function event(Activity $activity, \DateTimeImmutable $recordedAt): array
    {
        [$category, $type, $outcome] = self::classify($activity);

        $event = [
            'kind' => 'event',
            'category' => $category,
            'type' => $type,
            'action' => $activity->action ?? self::defaultAction($activity->type),
            'id' => $activity->eventId,
            'created' => self::formatDate($recordedAt),
            'dataset' => 'vigie.activity',
        ];

        if (null !== $outcome) {
            $event['outcome'] = $outcome;
        }

        return $event;
    }

    /**
     * @return array{0: list<string>, 1: list<string>, 2: ?string}
     */
    private static function classify(Activity $activity): array
    {
        return match ($activity->type) {
            ActivityType::HttpRequest => [['web'], ['access'], ($activity->statusCode ?? 0) < 400 ? 'success' : 'failure'],
            ActivityType::LoginSuccess => [['authentication'], ['start'], 'success'],
            ActivityType::LoginFailure => [['authentication'], true === ($activity->context['throttled'] ?? null) ? ['start', 'denied'] : ['start'], 'failure'],
            ActivityType::Logout => [['authentication'], ['end'], 'success'],
            ActivityType::SwitchUser => [['authentication', 'iam'], ['exit' === ($activity->context['direction'] ?? null) ? 'end' : 'start'], 'success'],
            ActivityType::TokenDeauthenticated => [['authentication'], ['end'], 'failure'],
            ActivityType::AccessDenied => [['authentication'], ['denied'], 'failure'],
            ActivityType::PasswordChanged, ActivityType::RolesChanged => [['iam'], ['user', 'change'], 'success'],
            ActivityType::CsrfFailure => [['web'], ['denied'], 'failure'],
            ActivityType::Custom => [[], ['info'], null],
        };
    }

    private static function defaultAction(ActivityType $type): string
    {
        return match ($type) {
            ActivityType::HttpRequest => 'http_request',
            ActivityType::LoginSuccess, ActivityType::LoginFailure => 'login',
            ActivityType::Logout => 'logout',
            ActivityType::SwitchUser => 'switch_user',
            ActivityType::TokenDeauthenticated => 'token_deauthenticated',
            ActivityType::AccessDenied => 'access_denied',
            ActivityType::PasswordChanged => 'password_changed',
            ActivityType::RolesChanged => 'roles_changed',
            ActivityType::CsrfFailure => 'csrf_failure',
            ActivityType::Custom => 'custom',
        };
    }

    /**
     * @return EcsVigie
     */
    private static function vigie(Activity $activity): array
    {
        $vigie = ['type' => $activity->type->value];

        if (null !== $activity->route) {
            $vigie['route'] = $activity->route;
        }

        if (null !== $activity->firewall) {
            $vigie['firewall'] = $activity->firewall;
        }

        if (null !== $activity->sessionId) {
            $vigie['session_id'] = $activity->sessionId;
        }

        if (null !== $activity->subject) {
            $vigie['subject'] = ['type' => $activity->subject->type, 'id' => $activity->subject->id];
        }

        if ([] !== $activity->context) {
            // Cast to object: json_encode() would otherwise render a
            // context whose keys happen to be numeric strings ("404") as a
            // JSON array instead of an object.
            $vigie['context'] = (object) $activity->context;
        }

        if (null !== $activity->remediation) {
            $vigie['remediation'] = $activity->remediation;
        }

        return $vigie;
    }

    /**
     * @return EcsUser
     */
    private static function user(Activity $activity): array
    {
        $user = [];

        if (null !== $activity->userIdentifier) {
            $key = self::looksHashed($activity->userIdentifier) ? 'hash' : 'name';
            $user[$key] = $activity->userIdentifier;
        }

        // Whichever is set: TokenProcessor's context.impersonator, or SecurityActivitySubscriber's
        // context.original_user on the switch_user activity — both mean "the real actor behind user.name".
        $effective = self::contextString($activity, 'impersonator') ?? self::contextString($activity, 'original_user');

        if (null !== $effective) {
            $user['effective'] = ['name' => $effective];
        }

        return $user;
    }

    /**
     * @return EcsSource|array{}
     */
    private static function source(Activity $activity): array
    {
        if (null === $activity->ipAddress) {
            return [];
        }

        $source = ['address' => $activity->ipAddress];

        $ip = self::validIp($activity->ipAddress);
        if (null !== $ip) {
            $source['ip'] = $ip;
        }

        return $source;
    }

    /**
     * @return EcsHttp
     */
    private static function http(Activity $activity): array
    {
        $request = [];
        if (null !== $activity->method) {
            $request['method'] = $activity->method;
        }
        if (null !== $activity->requestId) {
            $request['id'] = $activity->requestId;
        }

        $http = [];

        if ([] !== $request) {
            $http['request'] = $request;
        }

        if (null !== $activity->statusCode) {
            $http['response'] = ['status_code' => $activity->statusCode];
        }

        return $http;
    }

    /**
     * @return EcsUrl|array{}
     */
    private static function url(Activity $activity): array
    {
        if (null === $activity->uri) {
            return [];
        }

        $parts = parse_url($activity->uri);
        $path = \is_array($parts) ? ($parts['path'] ?? $activity->uri) : $activity->uri;

        $url = ['path' => $path];

        if (\is_array($parts) && isset($parts['query']) && '' !== $parts['query']) {
            $url['query'] = $parts['query'];
        }

        return $url;
    }

    /**
     * @return EcsRelated
     */
    private static function related(Activity $activity): array
    {
        $related = [];

        /** @var list<string> $users */
        $users = [];
        foreach ([$activity->userIdentifier, self::contextString($activity, 'impersonator'), self::contextString($activity, 'original_user')] as $candidate) {
            if (null !== $candidate) {
                $users[] = $candidate;
            }
        }
        $users = array_values(array_unique($users));

        if ([] !== $users) {
            $related['user'] = $users;
        }

        $ip = self::validIp($activity->ipAddress);
        if (null !== $ip) {
            $related['ip'] = [$ip];
        }

        return $related;
    }

    private static function contextString(Activity $activity, string $key): ?string
    {
        $value = $activity->context[$key] ?? null;

        return \is_string($value) && '' !== $value ? $value : null;
    }

    private static function validIp(?string $value): ?string
    {
        if (null === $value) {
            return null;
        }

        return false !== filter_var($value, \FILTER_VALIDATE_IP) ? $value : null;
    }

    private static function looksHashed(string $value): bool
    {
        return 1 === preg_match(self::HASH_PATTERN, $value);
    }

    private static function formatDate(\DateTimeImmutable $dateTime): string
    {
        return $dateTime->setTimezone(new \DateTimeZone('UTC'))->format(self::DATE_FORMAT);
    }
}
