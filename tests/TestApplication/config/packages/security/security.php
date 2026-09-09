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

use Symfony\Component\Security\Core\User\InMemoryUser;

return static function (ContainerConfigurator $container): void {
    $container->extension('security', [
        'password_hashers' => [
            InMemoryUser::class => 'plaintext',
        ],
        'providers' => [
            'in_memory' => [
                'memory' => [
                    'users' => [
                        'jane.doe' => ['password' => 'password', 'roles' => ['ROLE_USER']],
                        'admin' => ['password' => 'password', 'roles' => ['ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH']],
                    ],
                ],
            ],
        ],
        'firewalls' => [
            'main' => [
                'pattern' => '^/',
                'provider' => 'in_memory',
                'http_basic' => true,
                'switch_user' => true,
                'logout' => true,
            ],
        ],
    ]);
};
