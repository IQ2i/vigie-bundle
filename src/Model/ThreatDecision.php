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

namespace IQ2i\VigieBundle\Model;

/**
 * An immutable, transport-friendly representation of a decision a SIEM (e.g.
 * CrowdSec) handed back about a suspicious IP, range, country, AS number, or
 * a provider-specific scope such as a session or a user identifier.
 *
 * An empty $provider, $externalId or $value is rejected rather than silently
 * nulled: these three together are the decision's identity and matching key.
 */
final readonly class ThreatDecision
{
    public string $provider;
    public string $externalId;
    public ThreatScope $scope;
    public string $value;
    public string $type;
    public \DateTimeImmutable $syncedAt;
    public ?\DateTimeImmutable $expiresAt;
    public ?string $origin;
    public ?string $scenario;

    /**
     * @param string              $provider   short, stable identifier of the SIEM this decision came from ("crowdsec")
     * @param string              $externalId the provider's own id for this decision
     * @param string              $value      the scope's value — an IP, a CIDR, a country code, an AS number, a
     *                                        session id or a user identifier, matching whatever $scope names.
     *                                        Normalized asymmetrically the same way ThreatScope::of() is: lowercased
     *                                        for a case-insensitive scope (uppercased instead for "Country", since
     *                                        CrowdSec emits those in uppercase), kept byte-for-byte otherwise
     * @param string              $type       the provider's own remediation type, lowercased ("ban", "captcha", a
     *                                        custom one) — see ThreatRemediation::priorityOf()
     * @param ?\DateTimeImmutable $expiresAt  null means the decision never expires on its own
     *
     * @throws \InvalidArgumentException if $provider, $externalId or $value is empty
     */
    public function __construct(
        string $provider,
        string $externalId,
        ThreatScope $scope,
        string $value,
        string $type,
        \DateTimeImmutable $syncedAt,
        ?\DateTimeImmutable $expiresAt = null,
        ?string $origin = null,
        ?string $scenario = null,
    ) {
        if ('' === $provider) {
            throw new \InvalidArgumentException('A ThreatDecision must have a non-empty provider.');
        }

        if ('' === $externalId) {
            throw new \InvalidArgumentException('A ThreatDecision must have a non-empty externalId.');
        }

        $trimmedValue = trim($value);

        if ('' === $trimmedValue) {
            throw new \InvalidArgumentException('A ThreatDecision must have a non-empty value.');
        }

        $this->provider = $provider;
        $this->externalId = $externalId;
        $this->scope = $scope;
        $this->value = $scope->normalizeValue($trimmedValue);
        $this->type = strtolower(trim($type));
        $this->syncedAt = $syncedAt;
        $this->expiresAt = $expiresAt;
        $this->origin = '' !== $origin ? $origin : null;
        $this->scenario = '' !== $scenario ? $scenario : null;
    }

    public function isActive(\DateTimeImmutable $now): bool
    {
        return null === $this->expiresAt || $this->expiresAt > $now;
    }

    public function priority(): int
    {
        return ThreatRemediation::priorityOf($this->type);
    }

    /**
     * Identity key, unique per store: what apply() upserts and deletes on,
     * and what ThreatChecker dedupes matching decisions by.
     */
    public function key(): string
    {
        return $this->provider.':'.$this->externalId;
    }
}
