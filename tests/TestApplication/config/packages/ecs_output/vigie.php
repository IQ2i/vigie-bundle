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
    // Everything else is left at its default: "monolog" storage with the built-in ECS formatter.
    $container->extension('iq2i_vigie', [
        'app' => 'shop',
        'http' => [
            'recorded_paths' => ['^/ping'],
        ],
    ]);
};
