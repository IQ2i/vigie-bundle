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

use IQ2i\VigieBundle\Tests\TestApplication\ForcingActivityDecider;

return static function (ContainerConfigurator $container): void {
    // Autoconfigured: implementing ActivityDeciderInterface is enough to be
    // tagged "vigie.activity_decider" and picked up by TrackingDecider.
    $container->services()
        ->set(ForcingActivityDecider::class)
        ->autoconfigure();

    $container->extension('iq2i_vigie', [
        'storage' => 'in_memory',
    ]);
};
