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
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

// Nothing is exposed until an application imports this file — the prefix is
// the application's to choose, as with @WebProfilerBundle:
//
//     # config/routes/vigie.yaml
//     vigie_threat_ingest:
//         resource: '@IQ2iVigieBundle/config/routes.php'
//         prefix: /vigie
//
// See doc/threat.md, including why the resulting path belongs outside every
// firewall.
return static function (RoutingConfigurator $routes): void {
    $routes->add('iq2i_vigie_threat_ingest', '/threat/ingest/{provider}')
        ->controller(IngestController::class)
        ->methods(['POST'])
        ->requirements(['provider' => '[A-Za-z0-9_-]+']);
};
