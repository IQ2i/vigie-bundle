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
            // The default file handler stays: syslog is added to it, never substituted.
            'syslog' => [
                'enabled' => '%env(bool:VIGIE_TEST_SYSLOG_ENABLED)%',
                'host' => '127.0.0.1',
                'port' => '%env(int:VIGIE_TEST_SYSLOG_PORT)%',
                'ident' => 'vigie-test',
            ],
        ],
    ]);
};
