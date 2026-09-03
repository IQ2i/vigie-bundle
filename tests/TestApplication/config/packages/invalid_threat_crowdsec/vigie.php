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
    // No "crowdsec.api_key" — booting must fail with a clear LogicException.
    $container->extension('iq2i_vigie', [
        'threat' => [
            'enabled' => true,
            'provider' => 'crowdsec',
        ],
    ]);
};
