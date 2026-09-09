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

namespace IQ2i\VigieBundle\Tests\Uid;

use IQ2i\VigieBundle\Uid\UidGenerator;
use PHPUnit\Framework\TestCase;

final class UidGeneratorTest extends TestCase
{
    public function testGenerateProducesAUuidV7WhenSymfonyUidIsAvailable(): void
    {
        $id = UidGenerator::generate();

        self::assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $id,
        );
    }

    public function testGenerateProducesDifferentIdsEachTime(): void
    {
        self::assertNotSame(UidGenerator::generate(), UidGenerator::generate());
    }
}
