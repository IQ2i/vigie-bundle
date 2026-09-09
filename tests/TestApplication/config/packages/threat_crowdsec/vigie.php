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
    // Proves the real DI wiring of the built-in CrowdSec provider against a MockHttpClient instead of a live LAPI.
    $container->extension('iq2i_vigie', [
        'threat' => [
            'enabled' => true,
            'provider' => 'crowdsec',
            'storage' => 'in_memory',
            'crowdsec' => [
                'api_key' => 'test-key',
                'http_client' => 'app.mock_http_client',
            ],
        ],
    ]);
};
