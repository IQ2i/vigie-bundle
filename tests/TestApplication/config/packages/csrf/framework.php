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
        // Enabling a session registers security.csrf.token_manager by default, on the whole supported Symfony range.
        'session' => [
            'storage_factory_id' => 'session.storage.factory.mock_file',
        ],
    ]);
};
