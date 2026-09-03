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

use Monolog\Handler\TestHandler;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set('app.test_handler', TestHandler::class)
        ->public();
};
