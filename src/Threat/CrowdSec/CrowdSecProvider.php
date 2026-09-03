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

namespace IQ2i\VigieBundle\Threat\CrowdSec;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Threat\ThreatProviderException;
use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Contracts\HttpClient\Exception\ExceptionInterface as HttpClientExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Consumes CrowdSec's Local API (LAPI) `/v1/decisions/stream` endpoint,
 * authenticated with a bouncer API key (`cscli bouncers add`). Can only pull
 * decisions, never push one back. The LAPI keeps the delta cursor server-side,
 * per API key; "started from scratch" is requested with the stream's own
 * `startup=true` query parameter — see doc/threat.md.
 *
 * @internal select it with `iq2i_vigie.threat.provider: crowdsec` rather than instantiating it directly.
 */
final readonly class CrowdSecProvider implements ThreatProviderInterface
{
    private const NAME = 'crowdsec';

    // The LAPI derives per-bouncer metrics from this header — its shape
    // matters, not just its presence.
    private const USER_AGENT = 'crowdsec-symfony-vigie-bouncer/v1';

    /**
     * @param list<string> $scopes              always sent explicitly — the LAPI's default ("ip,range") would silently drop a custom scope configured here but not listed
     * @param list<string> $origins
     * @param list<string> $scenariosContaining
     */
    public function __construct(
        private HttpClientInterface $client,
        private string $apiKey,
        private array $scopes = ['Ip', 'Range'],
        private array $origins = [],
        private array $scenariosContaining = [],
        private ClockInterface $clock = new Clock(),
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function pull(bool $startup): ThreatSyncBatch
    {
        $query = [
            'startup' => $startup ? 'true' : 'false',
            'scopes' => implode(',', $this->scopes),
        ];

        if ([] !== $this->origins) {
            $query['origins'] = implode(',', $this->origins);
        }

        if ([] !== $this->scenariosContaining) {
            $query['scenarios_containing'] = implode(',', $this->scenariosContaining);
        }

        [$status, $content] = $this->request($query);

        if (403 === $status) {
            throw new ThreatProviderException('The CrowdSec LAPI rejected the API key — check iq2i_vigie.threat.crowdsec.api_key against "cscli bouncers list".');
        }

        if (200 !== $status) {
            throw new ThreatProviderException(\sprintf('The CrowdSec LAPI answered HTTP %d: %s', $status, self::errorMessage($content)));
        }

        return $this->toBatch($content);
    }

    /**
     * @param array<string, string> $query
     *
     * @return array{0: int, 1: string} [status code, raw body]
     */
    private function request(array $query): array
    {
        try {
            $response = $this->client->request('GET', '/v1/decisions/stream', [
                'query' => $query,
                'headers' => [
                    'X-Api-Key' => $this->apiKey,
                    'User-Agent' => self::USER_AGENT,
                ],
            ]);

            return [$response->getStatusCode(), $response->getContent(false)];
        } catch (HttpClientExceptionInterface $e) {
            throw new ThreatProviderException(\sprintf('Could not reach the CrowdSec LAPI: %s', $e->getMessage()), previous: $e);
        }
    }

    private function toBatch(string $content): ThreatSyncBatch
    {
        try {
            $payload = json_decode($content, true, 8, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new ThreatProviderException('The CrowdSec LAPI answered invalid JSON.', previous: $e);
        }

        // A stream with nothing to report answers a literal JSON "null" body
        // — not "[]", not "{}" — so $payload is normalized before either key
        // is read from it.
        $payload = \is_array($payload) ? $payload : [];
        $rawNew = \is_array($payload['new'] ?? null) ? $payload['new'] : [];
        $rawDeleted = \is_array($payload['deleted'] ?? null) ? $payload['deleted'] : [];

        $now = $this->clock->now();
        $added = [];
        $removed = [];
        $skipped = 0;

        foreach ($rawNew as $raw) {
            if (!\is_array($raw)) {
                ++$skipped;

                continue;
            }

            /** @var array<string, mixed> $raw */
            $decision = self::decisionFromArray($raw, $now);

            if (null === $decision) {
                ++$skipped;
                $this->logger?->debug('Vigie skipped a CrowdSec decision it could not read.', ['raw' => $raw]);

                continue;
            }

            $added[] = $decision;
        }

        foreach ($rawDeleted as $raw) {
            if (!\is_array($raw)) {
                ++$skipped;

                continue;
            }

            /** @var array<string, mixed> $raw */
            $decision = self::decisionIdentityFromArray($raw, $now);

            if (null === $decision) {
                ++$skipped;

                continue;
            }

            $removed[] = $decision;
        }

        return new ThreatSyncBatch($added, $removed, $skipped);
    }

    private static function errorMessage(string $content): string
    {
        try {
            $decoded = json_decode($content, true, 4, \JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $content;
        }

        $message = \is_array($decoded) ? $decoded['message'] ?? null : null;

        return \is_string($message) && '' !== $message ? $message : $content;
    }

    /**
     * A "new" entry: {id, origin, type, scope, value, duration, scenario, uuid}. $now anchors the whole
     * batch's expiresAt computation, computed once per batch rather than once per decision. Returns null
     * rather than throwing on anything unreadable.
     *
     * @param array<string, mixed> $raw
     */
    private static function decisionFromArray(array $raw, \DateTimeImmutable $now): ?ThreatDecision
    {
        $externalId = self::externalId($raw['id'] ?? null);
        $scope = $raw['scope'] ?? null;
        $value = $raw['value'] ?? null;
        $type = $raw['type'] ?? null;
        $duration = $raw['duration'] ?? null;

        if (null === $externalId || !\is_string($scope) || '' === $scope
            || !\is_string($value) || '' === $value
            || !\is_string($type) || '' === $type
            || !\is_string($duration)
        ) {
            return null;
        }

        $seconds = GoDurationParser::toSeconds($duration);

        // A duration that can't be parsed, or one that's already <= 0 (clock
        // drift between this host and the LAPI, a slow request), is treated
        // as already expired — never clamped to a minimum, which would
        // produce a ban nothing would ever purge.
        if (null === $seconds || $seconds <= 0) {
            return null;
        }

        $origin = $raw['origin'] ?? null;
        $scenario = $raw['scenario'] ?? null;

        // DateInterval has no fractional-second component, and DateTimeImmutable::modify()'s relative parser
        // mishandles a fractional "+N.NNNNNN seconds" string — rounded up instead, so a sub-second decision
        // (a "300ms" duration) still lands one full second in the future rather than zero.
        $expiresAt = $now->add(new \DateInterval('PT'.(int) ceil($seconds).'S'));

        return new ThreatDecision(
            provider: self::NAME,
            externalId: $externalId,
            scope: ThreatScope::of($scope),
            value: $value,
            type: $type,
            syncedAt: $now,
            expiresAt: $expiresAt,
            origin: \is_string($origin) ? $origin : null,
            scenario: \is_string($scenario) ? $scenario : null,
        );
    }

    /**
     * A "deleted" entry — only its identity (ThreatDecision::key()) is ever
     * read by ThreatDecisionStoreInterface::apply(); "duration" is ignored,
     * since it can legitimately be negative here.
     *
     * @param array<string, mixed> $raw
     */
    private static function decisionIdentityFromArray(array $raw, \DateTimeImmutable $now): ?ThreatDecision
    {
        $externalId = self::externalId($raw['id'] ?? null);
        $scope = $raw['scope'] ?? null;
        $value = $raw['value'] ?? null;

        if (null === $externalId || !\is_string($scope) || '' === $scope || !\is_string($value) || '' === $value) {
            return null;
        }

        $type = $raw['type'] ?? null;

        return new ThreatDecision(
            provider: self::NAME,
            externalId: $externalId,
            scope: ThreatScope::of($scope),
            value: $value,
            type: \is_string($type) && '' !== $type ? $type : 'ban',
            syncedAt: $now,
        );
    }

    private static function externalId(mixed $id): ?string
    {
        return match (true) {
            \is_int($id) => (string) $id,
            \is_string($id) && '' !== $id => $id,
            default => null,
        };
    }
}
