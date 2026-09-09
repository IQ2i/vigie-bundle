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
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;

final class CsrfFailureTest extends FunctionalTestCase
{
    public function testAnInvalidTokenIsRecordedAndTheResponseIsUnchanged(): void
    {
        $client = static::createClient(['environment' => 'csrf']);
        $client->disableReboot();

        $client->request('POST', '/csrf', ['token' => 'wrong']);

        self::assertSame(200, $client->getResponse()->getStatusCode());

        /** @var array{valid: bool} $body */
        $body = json_decode((string) $client->getResponse()->getContent(), true, flags: \JSON_THROW_ON_ERROR);
        self::assertFalse($body['valid']);

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = array_values(array_filter(
            $storage->all(),
            static fn (Activity $activity): bool => ActivityType::CsrfFailure === $activity->type,
        ));

        self::assertCount(1, $activities);
        self::assertSame('authenticate', $activities[0]->context['token_id'] ?? null);
    }
}
