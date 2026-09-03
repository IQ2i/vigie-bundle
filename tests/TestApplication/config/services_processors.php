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

use IQ2i\VigieBundle\Tests\TestApplication\Controller\CustomActivityController;
use IQ2i\VigieBundle\Tests\TestApplication\TenantProcessor;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(CustomActivityController::class)
        ->autowire()
        ->public();

    // Autoconfigured: implementing ActivityProcessorInterface is enough to
    // be tagged "vigie.activity_processor" and run for every activity.
    $container->services()
        ->set(TenantProcessor::class)
        ->autoconfigure();
};
