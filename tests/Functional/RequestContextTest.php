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

use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;

final class RequestContextTest extends FunctionalTestCase
{
    public function testATrackedRequestCarriesTheRequestContext(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/ping');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();
        self::assertCount(1, $activities);

        $context = $activities[0]->context;

        self::assertArrayHasKey('host', $context);
        self::assertArrayHasKey('scheme', $context);
        self::assertArrayHasKey('duration_ms', $context);
        self::assertFalse($context['authenticated']);
        self::assertArrayNotHasKey('exception_class', $context);
    }

    public function testAFailingRequestCarriesTheExceptionClass(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/failing');

        self::assertSame(500, $client->getResponse()->getStatusCode());

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();
        self::assertCount(1, $activities);

        self::assertSame('RuntimeException', $activities[0]->context['exception_class']);
    }
}
