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
    // No "provider" — proves the ingest endpoint works without a pull
    // provider configured at all.
    $container->extension('iq2i_vigie', [
        'threat' => [
            'enabled' => true,
            'storage' => 'in_memory',
            'ingest' => [
                'enabled' => true,
                'providers' => [
                    'wazuh' => 'test-secret',
                ],
            ],
        ],
    ]);
};
