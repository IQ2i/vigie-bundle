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

// Same firewall as the "security" environment: http_basic sets its own response on both success and
// failure, so this is enough to reproduce ThreatEnforcementSubscriber running (or not) before it does.
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
                    ],
                ],
            ],
        ],
        'firewalls' => [
            'main' => [
                'pattern' => '^/',
                'provider' => 'in_memory',
                'http_basic' => true,
            ],
        ],
    ]);
};
