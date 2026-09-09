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
    $container->extension('framework', [
        'profiler' => [
            'collect' => true,
            'only_exceptions' => false,
        ],
    ]);

    $container->extension('web_profiler', [
        'toolbar' => false,
        'intercept_redirects' => false,
    ]);
};
