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

namespace IQ2i\VigieBundle\Test;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use PHPUnit\Framework\Assert;

/**
 * Assertions over the bundle's in-memory test double — set
 * `iq2i_vigie.storage: in_memory` in a test environment, drive your
 * application, then assert against what got recorded. See doc/testing.md
 * for a full example.
 *
 * Delegates to PHPUnit\Framework\Assert statically rather than extending a
 * PHPUnit base class or a Constraint, so it stays usable from any test case
 * (or none).
 */
trait VigieAssertionsTrait
{
    /**
     * @param callable(Activity): bool|ActivityType $matcher an ActivityType matches on
     *                                                       `$activity->type`; a callable
     *                                                       matches on anything else
     */
    public static function assertActivityRecorded(InMemoryActivityStorage $storage, callable|ActivityType $matcher, string $message = ''): void
    {
        Assert::assertTrue(self::anyActivityMatches($storage, $matcher), '' !== $message ? $message : 'Failed asserting that a matching activity was recorded.');
    }

    /**
     * @param callable(Activity): bool|ActivityType $matcher
     */
    public static function assertActivityNotRecorded(InMemoryActivityStorage $storage, callable|ActivityType $matcher, string $message = ''): void
    {
        Assert::assertFalse(self::anyActivityMatches($storage, $matcher), '' !== $message ? $message : 'Failed asserting that no matching activity was recorded.');
    }

    /**
     * @param ?callable(Activity): bool $matcher counts every recorded activity when omitted
     */
    public static function assertActivityCount(InMemoryActivityStorage $storage, int $expectedCount, ?callable $matcher = null, string $message = ''): void
    {
        $matching = null !== $matcher ? array_values(array_filter($storage->all(), $matcher)) : $storage->all();

        Assert::assertCount($expectedCount, $matching, $message);
    }

    /**
     * @param callable(Activity): bool|ActivityType $matcher
     */
    private static function anyActivityMatches(InMemoryActivityStorage $storage, callable|ActivityType $matcher): bool
    {
        $callback = $matcher instanceof ActivityType
            ? static fn (Activity $activity): bool => $activity->type === $matcher
            : $matcher;

        foreach ($storage->all() as $activity) {
            if ($callback($activity)) {
                return true;
            }
        }

        return false;
    }
}
