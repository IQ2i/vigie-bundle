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

namespace IQ2i\VigieBundle\Storage;

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Threat\IpRange;

/**
 * ThreatDecisionQuery filtering logic shared by InMemoryThreatDecisionStore
 * and CacheThreatDecisionStore — not part of the bundle's public API.
 *
 * @internal
 */
trait ThreatDecisionMatching
{
    private static function matches(ThreatDecision $decision, ThreatDecisionQuery $query): bool
    {
        if ([] !== $query->scopes && !self::matchesAnyScope($decision, $query->scopes)) {
            return false;
        }

        if (null !== $query->value && $query->value !== $decision->value) {
            return false;
        }

        if (null !== $query->matchIp && !self::matchesIp($decision, $query->matchIp)) {
            return false;
        }

        if (null !== $query->provider && $query->provider !== $decision->provider) {
            return false;
        }

        if (null !== $query->activeAt && !$decision->isActive($query->activeAt)) {
            return false;
        }

        return true;
    }

    private static function matchesIp(ThreatDecision $decision, string $ip): bool
    {
        // Only Ip/Range scopes are ever matched by address: a custom scope
        // whose value looks like an address is not an address decision.
        if (!$decision->scope->equals(ThreatScope::ip()) && !$decision->scope->equals(ThreatScope::range())) {
            return false;
        }

        $range = IpRange::parse($decision->value);
        $target = IpRange::pack($ip);

        if (null === $range || null === $target) {
            return false;
        }

        return strcmp($target, $range[0]) >= 0 && strcmp($target, $range[1]) <= 0;
    }

    /**
     * @param list<ThreatScope> $scopes
     */
    private static function matchesAnyScope(ThreatDecision $decision, array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($decision->scope->equals($scope)) {
                return true;
            }
        }

        return false;
    }
}
