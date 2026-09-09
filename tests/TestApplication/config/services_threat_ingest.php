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

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use IQ2i\VigieBundle\Tests\TestApplication\ThreatCheckerHolder;
use IQ2i\VigieBundle\Tests\TestApplication\ThreatSyncCounter;
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services->set(ThreatSyncCounter::class)
        ->autoconfigure()
        ->public();

    $services->set(ThreatCheckerHolder::class)
        ->arg('$checker', service(ThreatCheckerInterface::class))
        ->public();
};
