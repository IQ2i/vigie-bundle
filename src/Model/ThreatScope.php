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
 * What a ThreatDecision's value identifies — an IP, a range, a country, an AS
 * number, or a provider-specific scope such as "session" or "user". of()
 * folds the four scopes this bundle knows about (Ip, Range, Country, AS) to
 * their canonical spelling, case insensitively; anything else is kept byte-for-byte.
 */
final readonly class ThreatScope
{
    public const IP = 'Ip';
    public const RANGE = 'Range';
    public const COUNTRY = 'Country';
    public const AS = 'AS';

    private const CANONICAL = [self::IP, self::RANGE, self::COUNTRY, self::AS];

    private function __construct(
        public string $value,
    ) {
    }

    public static function ip(): self
    {
        return new self(self::IP);
    }

    public static function range(): self
    {
        return new self(self::RANGE);
    }

    public static function country(): self
    {
        return new self(self::COUNTRY);
    }

    public static function asn(): self
    {
        return new self(self::AS);
    }

    public static function of(string $raw): self
    {
        $trimmed = trim($raw);

        foreach (self::CANONICAL as $canonical) {
            if (0 === strcasecmp($trimmed, $canonical)) {
                return new self($canonical);
            }
        }

        return new self($trimmed);
    }

    public function isCaseInsensitive(): bool
    {
        return \in_array($this->value, self::CANONICAL, true);
    }

    /**
     * The same transformation ThreatDecision applies to a value at storage
     * time, so a looked-up value matches what was actually stored:
     * lowercased for a case-insensitive scope, uppercased for "Country"
     * (which CrowdSec emits uppercase), byte-for-byte otherwise.
     */
    public function normalizeValue(string $value): string
    {
        $trimmed = trim($value);

        return match (true) {
            self::COUNTRY === $this->value => strtoupper($trimmed),
            $this->isCaseInsensitive() => strtolower($trimmed),
            default => $trimmed,
        };
    }

    public function equals(self $other): bool
    {
        return $this->value === $other->value;
    }
}
