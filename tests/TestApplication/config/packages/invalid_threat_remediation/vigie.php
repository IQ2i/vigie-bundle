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
    // 999 is not a valid HTTP error status code — booting must fail with a
    // clear InvalidConfigurationException.
    $container->extension('iq2i_vigie', [
        'threat' => [
            'enabled' => true,
            'storage' => 'in_memory',
            'enforce' => [
                'enabled' => true,
                'remediations' => [
                    'ban' => 999,
                ],
            ],
        ],
    ]);
};
