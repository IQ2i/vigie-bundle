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

use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;

final class BundleDisabledTest extends FunctionalTestCase
{
    public function testNoServiceIsRegistered(): void
    {
        self::bootKernel(['environment' => 'disabled']);

        self::assertFalse(self::getContainer()->has(ActivityRecorderInterface::class));
    }
}
