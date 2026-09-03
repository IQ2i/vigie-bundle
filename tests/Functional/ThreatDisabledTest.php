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

use IQ2i\VigieBundle\Command\ListThreatDecisionsCommand;
use IQ2i\VigieBundle\Command\SyncThreatDecisionsCommand;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use IQ2i\VigieBundle\Threat\Ingest\IngestController;
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;

final class ThreatDisabledTest extends FunctionalTestCase
{
    public function testNoThreatServiceIsRegisteredByDefault(): void
    {
        self::bootKernel();

        self::assertFalse(self::getContainer()->has(ThreatCheckerInterface::class));
        self::assertFalse(self::getContainer()->has(ThreatDecisionStoreInterface::class));
        self::assertFalse(self::getContainer()->has(SyncThreatDecisionsCommand::class));
        self::assertFalse(self::getContainer()->has(ListThreatDecisionsCommand::class));
        self::assertFalse(self::getContainer()->has(IngestController::class));
    }
}
