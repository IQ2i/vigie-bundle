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

return static function (ContainerConfigurator $container): void {
    $container->extension('iq2i_vigie', [
        'http' => [
            'recorded_paths' => ['^/ping'],
        ],
        'output' => [
            // A handler referenced by id: Vigie must never touch its
            // formatter, nor register its own default one — see
            // services_ecs_output_custom_handler.php.
            'handlers' => ['app.test_handler'],
        ],
    ]);
};
