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

use IQ2i\VigieBundle\Tests\TestApplication\CollectingLogger;

final class StorageFailureTest extends FunctionalTestCase
{
    public function testAThrowingStorageDoesNotBreakTheResponseAndIsLogged(): void
    {
        $client = static::createClient(['environment' => 'storage_failure']);

        $client->request('GET', '/ping');

        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertSame('pong', $client->getResponse()->getContent());

        /** @var CollectingLogger $logger */
        $logger = self::getContainer()->get('logger');

        $errors = array_values(array_filter($logger->records, static fn (array $record): bool => 'error' === $record['level']));

        self::assertNotEmpty($errors);
        self::assertStringContainsString('could not record', $errors[0]['message']);
    }
}
