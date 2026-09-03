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
        // Enabling a session is what makes framework.csrf_protection
        // resolve enabled by default, which is what registers
        // security.csrf.token_manager at all — see FrameworkExtension::
        // registerSecurityCsrfConfiguration(). Session-based rather than
        // "stateless_token_ids" so this boots on the whole supported
        // Symfony range (6.4|7.4|8.0), not only 7.2+.
        'session' => [
            'storage_factory_id' => 'session.storage.factory.mock_file',
        ],
    ]);
};
