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
    // The default "cache.app" is filesystem-backed and would survive across
    // test runs sharing the same cache dir — an in-memory pool keeps the
    // ingest anti-replay guard isolated per test.
    $container->extension('framework', [
        'cache' => [
            'app' => 'cache.adapter.array',
        ],
    ]);
};
