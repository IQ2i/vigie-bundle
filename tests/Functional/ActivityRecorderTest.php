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

namespace IQ2i\VigieBundle\Tests\Functional;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;

final class ActivityRecorderTest extends FunctionalTestCase
{
    public function testRecordReachesTheConfiguredStorage(): void
    {
        self::bootKernel(['environment' => 'test_kit']);

        /** @var ActivityRecorderInterface $recorder */
        $recorder = self::getContainer()->get(ActivityRecorderInterface::class);

        $recorder->record(Activity::security(
            type: ActivityType::LoginSuccess,
            occurredAt: new \DateTimeImmutable('2026-08-21 10:00:00'),
            userIdentifier: 'jane.doe',
        ));

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('jane.doe', $activities[0]->userIdentifier);
    }
}
