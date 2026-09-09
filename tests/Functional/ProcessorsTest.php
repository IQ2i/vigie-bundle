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

final class ProcessorsTest extends FunctionalTestCase
{
    public function testCustomActivityIsEnrichedTheSameWayAsTheHttpRequestActivity(): void
    {
        $client = self::createClient(['environment' => 'processors']);
        $client->disableReboot();

        $client->request('GET', '/custom-activity');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        $activities = $storage->all();
        self::assertCount(2, $activities);

        $custom = self::findByType($activities, ActivityType::Custom);
        $http = self::findByType($activities, ActivityType::HttpRequest);

        self::assertSame('ping.hit', $custom->action);
        self::assertSame($http->ipAddress, $custom->ipAddress);
        self::assertSame($http->requestId, $custom->requestId);
        self::assertSame('acme', $custom->context['tenant']);
        self::assertSame('acme', $http->context['tenant']);
    }

    /**
     * @param list<\IQ2i\VigieBundle\Model\Activity> $activities
     */
    private static function findByType(array $activities, ActivityType $type): \IQ2i\VigieBundle\Model\Activity
    {
        foreach ($activities as $activity) {
            if ($type === $activity->type) {
                return $activity;
            }
        }

        self::fail(\sprintf('No activity of type "%s" was recorded.', $type->value));
    }
}
