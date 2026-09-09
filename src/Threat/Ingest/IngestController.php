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

namespace IQ2i\VigieBundle\Threat\Ingest;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Threat\ThreatSyncBatch;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Applies a batch of decisions a SIEM pushed, the mirror image of
 * ThreatSynchronizer::sync(). The shared secret's signature is the only
 * authentication: this route belongs outside every firewall.
 *
 * @internal
 */
final readonly class IngestController
{
    /**
     * @param array<string, string> $secrets one shared secret per provider name, from
     *                                       iq2i_vigie.threat.ingest.providers
     */
    public function __construct(
        private ThreatSynchronizer $synchronizer,
        private CacheItemPoolInterface $replayPool,
        private array $secrets,
        private int $maxBodySize,
        private int $clockSkew,
        private ClockInterface $clock = new Clock(),
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function __invoke(Request $request, string $provider): Response
    {
        $declaredLength = $request->headers->get('Content-Length');

        if (null !== $declaredLength && (int) $declaredLength > $this->maxBodySize) {
            return $this->refuse(Response::HTTP_REQUEST_ENTITY_TOO_LARGE, $provider, 'the declared Content-Length exceeds threat.ingest.max_body_size');
        }

        $body = $request->getContent();

        if (\strlen($body) > $this->maxBodySize) {
            return $this->refuse(Response::HTTP_REQUEST_ENTITY_TOO_LARGE, $provider, 'the body exceeds threat.ingest.max_body_size');
        }

        // A 404 here tells an unauthenticated caller which provider names exist.
        $secret = $this->secrets[$provider] ?? null;

        if (null === $secret) {
            return $this->refuse(Response::HTTP_NOT_FOUND, $provider, 'no secret is configured for this provider');
        }

        $timestamp = $request->headers->get(RequestSigner::TIMESTAMP_HEADER);
        $signature = $request->headers->get(RequestSigner::SIGNATURE_HEADER);

        if (null === $timestamp || null === $signature || 1 !== preg_match('/^\d{1,10}$/', $timestamp)) {
            return $this->refuse(Response::HTTP_UNAUTHORIZED, $provider, 'a signature or timestamp header is missing or malformed');
        }

        if (abs($this->clock->now()->getTimestamp() - (int) $timestamp) > $this->clockSkew) {
            return $this->refuse(Response::HTTP_UNAUTHORIZED, $provider, 'the timestamp is outside threat.ingest.clock_skew');
        }

        if (!RequestSigner::verify($secret, $timestamp, $body, $signature)) {
            return $this->refuse(Response::HTTP_UNAUTHORIZED, $provider, 'the signature does not match');
        }

        // Checked only after verification: an unauthenticated caller must not
        // be able to fill the pool with keys of its own choosing.
        if ($this->isReplay($provider, $signature)) {
            return $this->refuse(Response::HTTP_UNAUTHORIZED, $provider, 'this signature was already accepted inside the clock skew window');
        }

        try {
            $payload = json_decode($body, true, 16, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return $this->refuse(Response::HTTP_BAD_REQUEST, $provider, 'the body is not valid JSON: '.$e->getMessage());
        }

        if (!\is_array($payload)) {
            return $this->refuse(Response::HTTP_BAD_REQUEST, $provider, 'the body is not a JSON object');
        }

        /** @var array<string, mixed> $payload */
        $report = $this->synchronizer->applyBatch(
            $provider,
            $this->toBatch($provider, $payload),
            true === ($payload['startup'] ?? false),
        );

        return new JsonResponse([
            'added' => $report['added'],
            'removed' => $report['removed'],
            'skipped' => $report['skipped'],
        ], Response::HTTP_ACCEPTED);
    }

    private function refuse(int $status, string $provider, string $reason): Response
    {
        $this->logger?->warning('Vigie refused a threat ingest push for "{provider}" with HTTP {status}: {reason}', [
            'provider' => $provider,
            'status' => $status,
            'reason' => $reason,
        ]);

        return new JsonResponse(['error' => Response::$statusTexts[$status] ?? 'Error'], $status);
    }

    private function isReplay(string $provider, string $signature): bool
    {
        $key = 'vigie_threat.ingest.'.$provider.'.'.substr($signature, 7);

        try {
            $item = $this->replayPool->getItem($key);

            if ($item->isHit()) {
                return true;
            }

            $this->replayPool->save($item->set(true)->expiresAfter($this->clockSkew));
        } catch (\Throwable $e) {
            $this->logger?->warning('Vigie could not reach the threat cache pool to guard against an ingest replay: {message}', [
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }

        return false;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function toBatch(string $provider, array $payload): ThreatSyncBatch
    {
        $now = $this->clock->now();
        $added = [];
        $removed = [];
        $skipped = 0;

        foreach (self::entries($payload, 'added') as $raw) {
            if (!\is_array($raw)) {
                ++$skipped;

                continue;
            }

            /** @var array<string, mixed> $raw */
            $decision = self::decisionFromArray($provider, $raw, $now);

            if (null === $decision) {
                ++$skipped;

                continue;
            }

            $added[] = $decision;
        }

        foreach (self::entries($payload, 'removed') as $raw) {
            if (!\is_array($raw)) {
                ++$skipped;

                continue;
            }

            /** @var array<string, mixed> $raw */
            $decision = self::decisionIdentityFromArray($provider, $raw, $now);

            if (null === $decision) {
                ++$skipped;

                continue;
            }

            $removed[] = $decision;
        }

        return new ThreatSyncBatch($added, $removed, $skipped);
    }

    /**
     * @param array<string, mixed> $payload
     *
     * @return list<mixed>
     */
    private static function entries(array $payload, string $key): array
    {
        $raw = $payload[$key] ?? null;

        return \is_array($raw) ? array_values($raw) : [];
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function decisionFromArray(string $provider, array $raw, \DateTimeImmutable $now): ?ThreatDecision
    {
        $externalId = self::externalId($raw['id'] ?? null);
        $scope = $raw['scope'] ?? null;
        $value = $raw['value'] ?? null;

        if (null === $externalId
            || !\is_string($scope) || '' === trim($scope)
            || !\is_string($value) || '' === trim($value)
        ) {
            return null;
        }

        $expiresAt = self::expiresAt($raw['expires_at'] ?? null);

        if (false === $expiresAt) {
            return null;
        }

        $type = $raw['type'] ?? null;
        $origin = $raw['origin'] ?? null;
        $scenario = $raw['scenario'] ?? null;

        return new ThreatDecision(
            provider: $provider,
            externalId: $externalId,
            scope: ThreatScope::of($scope),
            value: $value,
            type: \is_string($type) && '' !== trim($type) ? $type : 'ban',
            syncedAt: $now,
            expiresAt: $expiresAt,
            origin: \is_string($origin) ? $origin : null,
            scenario: \is_string($scenario) ? $scenario : null,
        );
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function decisionIdentityFromArray(string $provider, array $raw, \DateTimeImmutable $now): ?ThreatDecision
    {
        $externalId = self::externalId($raw['id'] ?? null);

        if (null === $externalId) {
            return null;
        }

        $scope = $raw['scope'] ?? null;
        $value = $raw['value'] ?? null;
        $type = $raw['type'] ?? null;

        return new ThreatDecision(
            provider: $provider,
            externalId: $externalId,
            scope: ThreatScope::of(\is_string($scope) && '' !== trim($scope) ? $scope : ThreatScope::IP),
            value: \is_string($value) && '' !== trim($value) ? $value : $externalId,
            type: \is_string($type) && '' !== trim($type) ? $type : 'ban',
            syncedAt: $now,
        );
    }

    /**
     * false for an unparsable date, null for "never expires".
     */
    private static function expiresAt(mixed $raw): \DateTimeImmutable|false|null
    {
        if (null === $raw) {
            return null;
        }

        if (!\is_string($raw)) {
            return false;
        }

        try {
            return new \DateTimeImmutable($raw);
        } catch (\DateMalformedStringException) {
            return false;
        }
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
