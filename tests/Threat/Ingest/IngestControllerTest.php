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

namespace IQ2i\VigieBundle\Tests\Threat\Ingest;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Threat\Ingest\IngestController;
use IQ2i\VigieBundle\Threat\Ingest\RequestSigner;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class IngestControllerTest extends TestCase
{
    private const SECRET = 'test-secret';
    private const NOW = '2026-08-21 10:00:00';

    private InMemoryThreatDecisionStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryThreatDecisionStore();
    }

    private function controller(?CacheItemPoolInterface $replayPool = null, int $maxBodySize = 1048576, int $clockSkew = 300): IngestController
    {
        return new IngestController(
            new ThreatSynchronizer(null, $this->store),
            $replayPool ?? new ArrayAdapter(),
            ['wazuh' => self::SECRET],
            $maxBodySize,
            $clockSkew,
            new MockClock(self::NOW),
        );
    }

    private function signedRequest(string $body, string $provider = 'wazuh', ?string $secret = self::SECRET, ?string $timestamp = null): Request
    {
        $timestamp ??= (string) (new MockClock(self::NOW))->now()->getTimestamp();

        $request = Request::create('/threat/ingest/'.$provider, 'POST', content: $body);

        if (null !== $secret) {
            $request->headers->set(RequestSigner::TIMESTAMP_HEADER, $timestamp);
            $request->headers->set(RequestSigner::SIGNATURE_HEADER, RequestSigner::sign($secret, $timestamp, $body));
        }

        return $request;
    }

    public function testASignedPushIsAppliedAndAccepted(): void
    {
        $body = json_encode([
            'added' => [
                ['id' => 'wz-1', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban', 'expires_at' => null],
            ],
        ], \JSON_THROW_ON_ERROR);

        $response = ($this->controller())($this->signedRequest($body), 'wazuh');

        self::assertSame(Response::HTTP_ACCEPTED, $response->getStatusCode());
        /** @var array{added: int, removed: int, skipped: int} $payload */
        $payload = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertSame(['added' => 1, 'removed' => 0, 'skipped' => 0], $payload);

        $found = $this->store->find(new ThreatDecisionQuery());
        self::assertCount(1, $found);
        self::assertSame('203.0.113.42', $found[0]->value);
        self::assertNull($found[0]->expiresAt);
    }

    /**
     * @return iterable<string, array{0: string, 1: bool, 2: ?string, 3: string, 4: int}>
     */
    public static function malformedPushes(): iterable
    {
        // [provider, sign?, timestamp override, body, expected status]
        yield 'unknown provider' => ['unknown-siem', true, null, '{}', Response::HTTP_NOT_FOUND];
        yield 'no signature at all' => ['wazuh', false, null, '{}', Response::HTTP_UNAUTHORIZED];
        yield 'timestamp outside the clock skew' => ['wazuh', true, '1000000000', '{}', Response::HTTP_UNAUTHORIZED];
        yield 'invalid JSON' => ['wazuh', true, null, '{not json', Response::HTTP_BAD_REQUEST];
        yield 'a JSON scalar instead of an object' => ['wazuh', true, null, '"just a string"', Response::HTTP_BAD_REQUEST];
    }

    #[DataProvider('malformedPushes')]
    public function testAMalformedPushIsRefusedAndTheStoreStaysEmpty(string $provider, bool $signed, ?string $timestamp, string $body, int $expectedStatus): void
    {
        $request = $signed
            ? $this->signedRequest($body, $provider, self::SECRET, $timestamp)
            : $this->signedRequest($body, $provider, null);

        $response = ($this->controller())($request, $provider);

        self::assertSame($expectedStatus, $response->getStatusCode());
        self::assertSame([], $this->store->find(new ThreatDecisionQuery()));
    }

    public function testAWrongSignatureIsRefused(): void
    {
        $request = $this->signedRequest('{}', secret: 'a-different-secret');

        $response = ($this->controller())($request, 'wazuh');

        self::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }

    public function testABodyLargerThanMaxBodySizeIsRefused(): void
    {
        $body = '{"added":[]}';
        $request = $this->signedRequest($body);

        $response = ($this->controller(maxBodySize: 5))($request, 'wazuh');

        self::assertSame(Response::HTTP_REQUEST_ENTITY_TOO_LARGE, $response->getStatusCode());
    }

    public function testADeclaredContentLengthAboveMaxBodySizeIsRefusedBeforeReadingTheBody(): void
    {
        $body = '{"added":[]}';
        $request = $this->signedRequest($body);
        $request->headers->set('Content-Length', (string) \strlen($body));

        $response = ($this->controller(maxBodySize: \strlen($body) - 1))($request, 'wazuh');

        self::assertSame(Response::HTTP_REQUEST_ENTITY_TOO_LARGE, $response->getStatusCode());
    }

    public function testAReplayedSignatureIsRefused(): void
    {
        $body = json_encode(['added' => [['id' => 'wz-1', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban']]], \JSON_THROW_ON_ERROR);
        $replayPool = new ArrayAdapter();
        $controller = $this->controller($replayPool);

        $first = $controller($this->signedRequest($body), 'wazuh');
        self::assertSame(Response::HTTP_ACCEPTED, $first->getStatusCode());

        $second = $controller($this->signedRequest($body), 'wazuh');
        self::assertSame(Response::HTTP_UNAUTHORIZED, $second->getStatusCode());

        self::assertCount(1, $this->store->find(new ThreatDecisionQuery()));
    }

    public function testAStartupPushReplacesTheProvidersDecisions(): void
    {
        $this->store->apply('wazuh', [
            new ThreatDecision('wazuh', 'stale', ThreatScope::ip(), '198.51.100.1', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $body = json_encode([
            'startup' => true,
            'added' => [['id' => 'wz-2', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban']],
        ], \JSON_THROW_ON_ERROR);

        $response = ($this->controller())($this->signedRequest($body), 'wazuh');

        self::assertSame(Response::HTTP_ACCEPTED, $response->getStatusCode());
        $found = $this->store->find(new ThreatDecisionQuery());
        self::assertCount(1, $found);
        self::assertSame('203.0.113.42', $found[0]->value);
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unreadableAddedEntries(): iterable
    {
        yield 'missing value' => [['id' => 'wz-2', 'scope' => 'Ip', 'type' => 'ban']];
        yield 'not an object' => ['just a string'];
        yield 'an unparsable expiry' => [['id' => 'wz-2', 'scope' => 'Ip', 'value' => '198.51.100.1', 'type' => 'ban', 'expires_at' => 'not-a-date']];
        yield 'a non-string expiry' => [['id' => 'wz-2', 'scope' => 'Ip', 'value' => '198.51.100.1', 'type' => 'ban', 'expires_at' => 12345]];
    }

    #[DataProvider('unreadableAddedEntries')]
    public function testAnUnreadableAddedEntryIsCountedAsSkipped(mixed $secondEntry): void
    {
        $body = json_encode([
            'added' => [
                ['id' => 'wz-1', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban'],
                $secondEntry,
            ],
        ], \JSON_THROW_ON_ERROR);

        $response = ($this->controller())($this->signedRequest($body), 'wazuh');

        /** @var array{added: int, removed: int, skipped: int} $payload */
        $payload = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertSame(['added' => 1, 'removed' => 0, 'skipped' => 1], $payload);
    }

    public function testARemovedEntryOnlyNeedsItsId(): void
    {
        $this->store->apply('wazuh', [
            new ThreatDecision('wazuh', 'wz-1', ThreatScope::ip(), '203.0.113.42', 'ban', new \DateTimeImmutable()),
        ], [], new \DateTimeImmutable());

        $body = json_encode(['removed' => [['id' => 'wz-1']]], \JSON_THROW_ON_ERROR);

        $response = ($this->controller())($this->signedRequest($body), 'wazuh');

        self::assertSame(Response::HTTP_ACCEPTED, $response->getStatusCode());
        self::assertSame([], $this->store->find(new ThreatDecisionQuery()));
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unreadableRemovedEntries(): iterable
    {
        yield 'missing id' => [['scope' => 'Ip', 'value' => '203.0.113.42']];
        yield 'not an object' => [42];
    }

    #[DataProvider('unreadableRemovedEntries')]
    public function testAnUnreadableRemovedEntryIsCountedAsSkipped(mixed $entry): void
    {
        $body = json_encode(['removed' => [$entry]], \JSON_THROW_ON_ERROR);

        $response = ($this->controller())($this->signedRequest($body), 'wazuh');

        /** @var array{added: int, removed: int, skipped: int} $payload */
        $payload = json_decode((string) $response->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertSame(['added' => 0, 'removed' => 0, 'skipped' => 1], $payload);
    }

    public function testAnUnusableReplayPoolDoesNotRefuseThePush(): void
    {
        $throwingPool = new class implements CacheItemPoolInterface {
            public function getItem(string $key): never
            {
                throw new \RuntimeException('cache is down');
            }

            /**
             * @return iterable<string, \Psr\Cache\CacheItemInterface>
             */
            public function getItems(array $keys = []): iterable
            {
                return [];
            }

            public function hasItem(string $key): bool
            {
                return false;
            }

            public function clear(): bool
            {
                return true;
            }

            public function deleteItem(string $key): bool
            {
                return true;
            }

            public function deleteItems(array $keys): bool
            {
                return true;
            }

            public function save(\Psr\Cache\CacheItemInterface $item): bool
            {
                return true;
            }

            public function saveDeferred(\Psr\Cache\CacheItemInterface $item): bool
            {
                return true;
            }

            public function commit(): bool
            {
                return true;
            }
        };

        $body = json_encode(['added' => [['id' => 'wz-1', 'scope' => 'Ip', 'value' => '203.0.113.42', 'type' => 'ban']]], \JSON_THROW_ON_ERROR);

        $response = ($this->controller($throwingPool))($this->signedRequest($body), 'wazuh');

        self::assertSame(Response::HTTP_ACCEPTED, $response->getStatusCode());
    }
}
