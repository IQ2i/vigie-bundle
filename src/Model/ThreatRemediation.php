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
 * How a ThreatDecision's remediation type ranks against another one's, when
 * several decisions match the same request — "ban" outranks "captcha", which
 * outranks "throttle". priorityOf() puts an unrecognized type last.
 */
final class ThreatRemediation
{
    public const BAN = 'ban';
    public const CAPTCHA = 'captcha';
    public const THROTTLE = 'throttle';

    private const PRIORITY = [
        self::BAN => 40,
        self::CAPTCHA => 30,
        self::THROTTLE => 20,
    ];

    private const DEFAULT_PRIORITY = 10;

    private function __construct()
    {
    }

    public static function priorityOf(string $type): int
    {
        return self::PRIORITY[strtolower(trim($type))] ?? self::DEFAULT_PRIORITY;
    }
}
