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
        'storage' => 'in_memory',
        'http' => [
            // A response posed on kernel.request (a 403, the captcha
            // redirect) short-circuits kernel.controller, so #[Track] never
            // gets a chance to run — only a path pattern still opts the
            // request in.
            'recorded_paths' => ['^/'],
        ],
        'threat' => [
            'enabled' => true,
            'storage' => 'in_memory',
            'enforce' => [
                'enabled' => true,
                'remediations' => [
                    'ban' => 403,
                    'captcha' => 'app_captcha',
                ],
            ],
        ],
    ]);
};
