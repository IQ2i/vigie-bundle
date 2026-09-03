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

namespace IQ2i\VigieBundle\Tests\Storage;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use PHPUnit\Framework\TestCase;

final class InMemoryActivityStorageTest extends TestCase
{
    public function testStoreThenAllRoundTripsWhatWasStored(): void
    {
        $storage = new InMemoryActivityStorage();

        $storage->store($this->activityAt('2026-08-21 09:00:00', userIdentifier: 'jane.doe'));
        $storage->store($this->activityAt('2026-08-21 10:00:00', userIdentifier: 'john.doe'));

        self::assertCount(2, $storage->all());
    }

    public function testSubjectSurvivesStore(): void
    {
        $storage = new InMemoryActivityStorage();

        $storage->store(Activity::custom('user.delete', new \DateTimeImmutable('2026-08-21 09:00:00'), subject: new Subject('user', 42)));

        self::assertEquals(new Subject('user', 42), $storage->all()[0]->subject);
    }

    private function activityAt(string $time, ?string $userIdentifier = null): Activity
    {
        return Activity::custom(action: 'test', occurredAt: new \DateTimeImmutable($time), userIdentifier: $userIdentifier);
    }
}
