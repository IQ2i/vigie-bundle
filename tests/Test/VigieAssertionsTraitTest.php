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

namespace IQ2i\VigieBundle\Tests\Test;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Test\VigieAssertionsTrait;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\TestCase;

final class VigieAssertionsTraitTest extends TestCase
{
    use VigieAssertionsTrait;

    public function testAssertActivityRecordedAndAssertActivityNotRecorded(): void
    {
        $storage = new InMemoryActivityStorage();
        $storage->store(Activity::security(type: ActivityType::LoginFailure, occurredAt: new \DateTimeImmutable(), userIdentifier: 'jane.doe'));

        self::assertActivityRecorded($storage, ActivityType::LoginFailure);
        self::assertActivityNotRecorded($storage, ActivityType::LoginSuccess);
    }

    public function testAssertActivityRecordedFailsWhenNoActivityMatches(): void
    {
        $storage = new InMemoryActivityStorage();

        $this->expectException(AssertionFailedError::class);

        self::assertActivityRecorded($storage, ActivityType::LoginFailure);
    }

    public function testAssertActivityCountWithAMatcher(): void
    {
        $storage = new InMemoryActivityStorage();
        $storage->store(Activity::security(type: ActivityType::LoginFailure, occurredAt: new \DateTimeImmutable(), userIdentifier: 'jane.doe'));
        $storage->store(Activity::security(type: ActivityType::LoginSuccess, occurredAt: new \DateTimeImmutable(), userIdentifier: 'jane.doe'));

        self::assertActivityCount($storage, 2);
        self::assertActivityCount($storage, 1, static fn (Activity $activity): bool => ActivityType::LoginFailure === $activity->type);
    }
}
