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

use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Test\VigieAssertionsTrait;

final class TestKitTest extends FunctionalTestCase
{
    use VigieAssertionsTrait;

    public function testARequestIsRecordedInTheInMemoryStorage(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/ping');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        self::assertActivityRecorded($storage, ActivityType::HttpRequest);
        self::assertActivityCount($storage, 1);
    }

    public function testAssertActivityNotRecordedPassesWhenNothingMatches(): void
    {
        self::bootKernel(['environment' => 'test_kit']);

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        self::assertActivityNotRecorded($storage, ActivityType::LoginFailure);
    }
}
