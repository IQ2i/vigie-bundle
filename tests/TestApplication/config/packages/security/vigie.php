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
        // in_memory so SecurityFlowTest can assert on what got recorded.
        'storage' => 'in_memory',
        'http' => [
            // #[Track] on SecurityController::protectedAction only takes
            // effect once the controller resolves; a failed login never
            // reaches it, so recorded_paths is what still opts /protected in.
            'recorded_paths' => ['^/protected'],
        ],
    ]);
};
