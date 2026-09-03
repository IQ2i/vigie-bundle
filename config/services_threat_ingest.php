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

use IQ2i\VigieBundle\Threat\Ingest\IngestController;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

// Imported by IQ2iVigieBundle::loadExtension() only when
// iq2i_vigie.threat.ingest.enabled is true. $replayPool/$secrets/
// $maxBodySize/$clockSkew are overridden by loadExtension() from
// iq2i_vigie.threat.ingest.* and iq2i_vigie.threat.cache.pool.
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(IngestController::class)
        ->arg('$synchronizer', service(ThreatSynchronizer::class))
        ->arg('$replayPool', service('cache.app'))
        ->arg('$secrets', [])
        ->arg('$maxBodySize', 1048576)
        ->arg('$clockSkew', 300)
        ->arg('$clock', service(ClockInterface::class))
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('controller.service_arguments')
        ->tag('monolog.logger', ['channel' => 'vigie']);
};
