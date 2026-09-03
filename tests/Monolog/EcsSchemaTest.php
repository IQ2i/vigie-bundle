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

namespace IQ2i\VigieBundle\Tests\Monolog;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Monolog\EcsDocument;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EcsSchemaTest extends TestCase
{
    // Hand-rolled check, no JSON Schema library.
    /**
     * @return array<string, mixed>
     */
    private function schema(): array
    {
        $json = file_get_contents(\dirname(__DIR__, 2).'/doc/schema/activity-2.0.json');
        \assert(false !== $json);

        return self::node(json_decode($json, true, flags: \JSON_THROW_ON_ERROR));
    }

    public function testTheSchemaDeclaresTheCurrentEcsVersion(): void
    {
        $properties = self::node($this->schema()['properties'] ?? null);
        $ecsProperties = self::node(self::node($properties['ecs'] ?? null)['properties'] ?? null);
        $version = self::node($ecsProperties['version'] ?? null);

        self::assertSame(EcsDocument::ECS_VERSION, $version['const'] ?? null);
    }

    public function testTheSchemaRequiresExactlyTheAlwaysPresentTopLevelFields(): void
    {
        $required = self::list($this->schema()['required'] ?? null);

        self::assertSame(['@timestamp', 'message', 'ecs', 'event', 'vigie'], $required);
    }

    /**
     * @return iterable<string, array{Activity}>
     */
    public static function activityProvider(): iterable
    {
        $now = new \DateTimeImmutable('2026-08-21 10:00:00');

        yield 'http_request' => [Activity::httpRequest(
            occurredAt: $now,
            method: 'GET',
            uri: '/admin/orders?page=2',
            statusCode: 403,
            route: 'app_admin_orders',
            userIdentifier: 'jane.doe',
            ipAddress: '203.0.113.42',
            userAgent: 'curl/8',
            context: ['tenant' => 'acme'],
            firewall: 'main',
            sessionId: 'hashed-session',
            requestId: 'req-1',
            subject: new Subject('order', 42),
        )];

        yield 'login_success' => [Activity::security(
            type: ActivityType::LoginSuccess,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            ipAddress: '203.0.113.42',
            context: ['authenticator' => 'FormLoginAuthenticator', 'interactive' => true],
        )];

        yield 'login_failure' => [Activity::security(
            type: ActivityType::LoginFailure,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            context: ['reason' => 'Invalid credentials.'],
        )];

        yield 'logout' => [Activity::security(type: ActivityType::Logout, occurredAt: $now, userIdentifier: 'jane.doe')];

        yield 'switch_user (enter, impersonated by TokenProcessor)' => [Activity::security(
            type: ActivityType::SwitchUser,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            context: ['direction' => 'enter', 'original_user' => 'admin', 'impersonator' => 'admin'],
        )];

        yield 'token_deauthenticated' => [Activity::security(type: ActivityType::TokenDeauthenticated, occurredAt: $now, userIdentifier: 'jane.doe')];

        yield 'access_denied' => [Activity::security(
            type: ActivityType::AccessDenied,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            context: ['attributes' => 'ROLE_ADMIN', 'subject_type' => 'App\\Entity\\Order'],
        )];

        yield 'password_changed' => [Activity::security(
            type: ActivityType::PasswordChanged,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            context: ['reason' => 'reset'],
        )];

        yield 'roles_changed' => [Activity::security(
            type: ActivityType::RolesChanged,
            occurredAt: $now,
            userIdentifier: 'jane.doe',
            context: ['added' => 'ROLE_ADMIN', 'removed' => 'ROLE_GUEST', 'by' => 'admin'],
        )];

        yield 'csrf_failure' => [Activity::security(
            type: ActivityType::CsrfFailure,
            occurredAt: $now,
            context: ['token_id' => 'authenticate'],
        )];

        yield 'custom' => [Activity::custom('export.completed', $now, context: ['rows' => 42])];

        yield 'http_request (enforced)' => [Activity::httpRequest(
            occurredAt: $now,
            method: 'GET',
            uri: '/admin',
            statusCode: 403,
            ipAddress: '203.0.113.42',
        )->withRemediation('ban')];
    }

    #[DataProvider('activityProvider')]
    public function testEveryEmittedKeyIsKnownToTheSchema(Activity $activity): void
    {
        // "message" isn't part of EcsDocument::fromActivity()'s own output —
        // EcsFormatter merges it in from the LogRecord's own message, the
        // same way it would for any Monolog record — but it's still part of
        // the contract this schema describes: the line actually written.
        $document = EcsDocument::fromActivity($activity, new \DateTimeImmutable('2026-08-21 10:00:01'), 'shop', 'prod')
            + ['message' => EcsDocument::message($activity)];
        $schema = $this->schema();

        foreach (self::list($schema['required'] ?? null) as $required) {
            $required = self::str($required);
            self::assertArrayHasKey($required, $document, \sprintf('"%s" is required by the schema but missing from the document.', $required));
        }

        $this->assertKeysKnownToSchema($document, $schema);
    }

    public function testEveryActivityTypeIsCoveredByTheVigieTypeEnum(): void
    {
        $properties = self::node($this->schema()['properties'] ?? null);
        $vigieProperties = self::node(self::node($properties['vigie'] ?? null)['properties'] ?? null);
        $enum = self::list(self::node($vigieProperties['type'] ?? null)['enum'] ?? null);

        foreach (ActivityType::cases() as $case) {
            self::assertContains($case->value, $enum, \sprintf('ActivityType::%s has no counterpart in the "vigie.type" enum — update doc/schema/activity-2.0.json.', $case->name));
        }
    }

    /**
     * @param array<array-key, mixed> $data
     * @param array<string, mixed>    $schemaNode
     */
    private function assertKeysKnownToSchema(array $data, array $schemaNode): void
    {
        $properties = self::node($schemaNode['properties'] ?? []);

        $unknown = array_diff(array_map(strval(...), array_keys($data)), array_keys($properties));
        self::assertSame([], $unknown, \sprintf('Unknown key(s) [%s] — not declared in the schema at this level.', implode(', ', $unknown)));

        foreach ($data as $key => $value) {
            $childSchema = self::node($properties[$key] ?? null);

            if (\is_array($value) && 'object' === ($childSchema['type'] ?? null) && [] !== $value && !array_is_list($value)) {
                $this->assertKeysKnownToSchema($value, $childSchema);
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function node(mixed $value): array
    {
        self::assertIsArray($value);

        /** @var array<string, mixed> $typed */
        $typed = $value;

        return $typed;
    }

    /**
     * @return list<mixed>
     */
    private static function list(mixed $value): array
    {
        self::assertIsArray($value);

        return array_values($value);
    }

    private static function str(mixed $value): string
    {
        self::assertIsString($value);

        return $value;
    }
}
