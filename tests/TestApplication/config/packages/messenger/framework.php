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

use IQ2i\VigieBundle\Tests\TestApplication\Messenger\DispatchedJob;

return static function (ContainerConfigurator $container): void {
    $container->extension('framework', [
        'messenger' => [
            'transports' => [
                // Queued, not handled synchronously: the point of this environment is to prove the
                // correlation survives past the request that dispatched it, into a worker consuming
                // the transport later. See MessengerCorrelationTest.
                'async' => 'in-memory://',
            ],
            'routing' => [
                DispatchedJob::class => 'async',
            ],
            'buses' => [
                'messenger.bus.default' => [
                    'middleware' => ['iq2i_vigie.messenger.activity_context'],
                ],
            ],
        ],
    ]);
};
