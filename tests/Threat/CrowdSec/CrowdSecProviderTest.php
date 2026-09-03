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

namespace IQ2i\VigieBundle\Tests\Threat\CrowdSec;

use IQ2i\VigieBundle\Threat\CrowdSec\CrowdSecProvider;
use IQ2i\VigieBundle\Threat\ThreatProviderException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class CrowdSecProviderTest extends TestCase
{
    public function testAWellFormedStreamResponseIsMappedToABatch(): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode([
            'new' => [
                ['id' => 1, 'origin' => 'crowdsec', 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '4h', 'scenario' => 'crowdsecurity/ssh-bf'],
            ],
            'deleted' => [
                ['id' => 2, 'scope' => 'Ip', 'value' => '5.6.7.8', 'duration' => '-2m11s'],
            ],
        ], \JSON_THROW_ON_ERROR)));

        $batch = (new CrowdSecProvider($client, 'a-key'))->pull(false);

        self::assertCount(1, $batch->added);
        self::assertSame('1.2.3.4', $batch->added[0]->value);
        self::assertSame('crowdsec', $batch->added[0]->origin);
        self::assertSame('crowdsecurity/ssh-bf', $batch->added[0]->scenario);
        self::assertCount(1, $batch->removed);
        self::assertSame('5.6.7.8', $batch->removed[0]->value);
        self::assertSame(0, $batch->skipped);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function emptyBodies(): iterable
    {
        // "null" is what the stream endpoint answers when there is nothing
        // to report — not "[]", not "{}".
        yield 'a literal null' => ['null'];
        yield 'an empty array' => ['[]'];
        yield 'an empty object' => ['{}'];
    }

    #[DataProvider('emptyBodies')]
    public function testAnEmptyBodyIsNormalizedToAnEmptyBatch(string $body): void
    {
        $batch = (new CrowdSecProvider(new MockHttpClient(new MockResponse($body)), 'a-key'))->pull(false);

        self::assertSame([], $batch->added);
        self::assertSame([], $batch->removed);
    }

    /**
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function unreadableNewEntries(): iterable
    {
        yield 'missing id' => [['type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '1h']];
        yield 'missing scope' => [['id' => 1, 'type' => 'ban', 'value' => '1.2.3.4', 'duration' => '1h']];
        yield 'missing value' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'duration' => '1h']];
        yield 'missing type' => [['id' => 1, 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '1h']];
        yield 'missing duration' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4']];
        yield 'unreadable duration' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => 'not-a-duration']];
        yield 'a negative duration — already expired' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '-1h']];
        yield 'a zero duration — already expired' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '0s']];
    }

    /**
     * @param array<string, mixed> $raw
     */
    #[DataProvider('unreadableNewEntries')]
    public function testAnUnreadableNewEntryIsSkippedRatherThanFailingTheWholeBatch(array $raw): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode(['new' => [$raw]], \JSON_THROW_ON_ERROR)));

        $batch = (new CrowdSecProvider($client, 'a-key'))->pull(false);

        self::assertSame([], $batch->added);
        self::assertSame(1, $batch->skipped);
    }

    public function testASubSecondDurationRoundsUpToAtLeastOneSecondRatherThanExpiringImmediately(): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode([
            'new' => [['id' => 1, 'type' => 'ban', 'scope' => 'Ip', 'value' => '1.2.3.4', 'duration' => '300ms']],
        ], \JSON_THROW_ON_ERROR)));

        $batch = (new CrowdSecProvider($client, 'a-key'))->pull(false);

        self::assertCount(1, $batch->added);
        self::assertTrue($batch->added[0]->isActive(new \DateTimeImmutable()));
    }

    public function testADeletedEntryOnlyNeedsItsIdentityNotItsDuration(): void
    {
        // "duration" is legitimately negative on a deleted entry — ignored.
        $client = new MockHttpClient(new MockResponse(json_encode([
            'deleted' => [['id' => 1, 'scope' => 'Ip', 'value' => '5.6.7.8', 'duration' => '-2m11s']],
        ], \JSON_THROW_ON_ERROR)));

        $batch = (new CrowdSecProvider($client, 'a-key'))->pull(false);

        self::assertCount(1, $batch->removed);
        self::assertSame('5.6.7.8', $batch->removed[0]->value);
    }

    public function testADeletedEntryWithAnIncompleteIdentityIsSkipped(): void
    {
        $client = new MockHttpClient(new MockResponse(json_encode([
            'deleted' => [['id' => 1]],
        ], \JSON_THROW_ON_ERROR)));

        $batch = (new CrowdSecProvider($client, 'a-key'))->pull(false);

        self::assertSame([], $batch->removed);
        self::assertSame(1, $batch->skipped);
    }

    /**
     * @return iterable<string, array{0: MockResponse, 1: string}>
     */
    public static function errorResponses(): iterable
    {
        yield '403' => [new MockResponse('', ['http_code' => 403]), '/cscli bouncers list/'];
        yield '400 with a LAPI message' => [new MockResponse(json_encode(['message' => 'invalid scope'], \JSON_THROW_ON_ERROR), ['http_code' => 400]), '/invalid scope/'];
    }

    #[DataProvider('errorResponses')]
    public function testAnErrorResponseThrowsAnActionableException(MockResponse $response, string $messagePattern): void
    {
        $this->expectException(ThreatProviderException::class);
        $this->expectExceptionMessageMatches($messagePattern);

        (new CrowdSecProvider(new MockHttpClient($response), 'a-key'))->pull(false);
    }

    public function testA500ResponseThrows(): void
    {
        $this->expectException(ThreatProviderException::class);

        (new CrowdSecProvider(new MockHttpClient(new MockResponse('boom', ['http_code' => 500])), 'a-key'))->pull(false);
    }

    public function testMalformedJsonThrowsAThreatProviderExceptionNotAJsonException(): void
    {
        $this->expectException(ThreatProviderException::class);

        (new CrowdSecProvider(new MockHttpClient(new MockResponse('{not json')), 'a-key'))->pull(false);
    }

    public function testAnUnreadableTransportFailureIsWrappedInAThreatProviderException(): void
    {
        $client = new MockHttpClient(static function (): never {
            throw new TransportException('connection refused');
        });

        $this->expectException(ThreatProviderException::class);

        (new CrowdSecProvider($client, 'a-key'))->pull(false);
    }

    /**
     * @return iterable<string, array{0: bool, 1: string}>
     */
    public static function startupValues(): iterable
    {
        yield 'no state, not forced' => [false, 'startup=false'];
        yield 'forced' => [true, 'startup=true'];
    }

    #[DataProvider('startupValues')]
    public function testStartupIsSentAsRequested(bool $startup, string $expected): void
    {
        $capturedQuery = null;
        $client = new MockHttpClient(static function (string $method, string $url) use (&$capturedQuery): MockResponse {
            $capturedQuery = $url;

            return new MockResponse('null');
        });

        (new CrowdSecProvider($client, 'a-key'))->pull($startup);

        self::assertStringContainsString($expected, (string) $capturedQuery);
    }

    public function testScopesOriginsAndScenariosContainingAreSentExplicitly(): void
    {
        $capturedQuery = null;
        $client = new MockHttpClient(static function (string $method, string $url) use (&$capturedQuery): MockResponse {
            $capturedQuery = $url;

            return new MockResponse('null');
        });

        $provider = new CrowdSecProvider($client, 'a-key', ['Ip', 'Range', 'session'], ['crowdsec', 'cscli'], ['http-']);
        $provider->pull(false);

        self::assertStringContainsString('scopes=Ip%2CRange%2Csession', (string) $capturedQuery);
        self::assertStringContainsString('origins=crowdsec%2Ccscli', (string) $capturedQuery);
        self::assertStringContainsString('scenarios_containing=http-', (string) $capturedQuery);
    }

    public function testTheApiKeyAndUserAgentHeadersAreSent(): void
    {
        $capturedHeaders = '';
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use (&$capturedHeaders): MockResponse {
            /** @var list<string> $headers */
            $headers = $options['headers'] ?? [];
            $capturedHeaders = implode("\n", $headers);

            return new MockResponse('null');
        });

        (new CrowdSecProvider($client, 'super-secret-key'))->pull(false);

        self::assertStringContainsString('X-Api-Key: super-secret-key', $capturedHeaders);
        self::assertStringContainsString('User-Agent: crowdsec-symfony-vigie-bouncer', $capturedHeaders);
    }
}
