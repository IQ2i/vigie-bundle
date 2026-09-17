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

use IQ2i\VigieBundle\Tests\TestApplication\Controller\MessengerDispatchController;
use IQ2i\VigieBundle\Tests\TestApplication\Messenger\DispatchedJobHandler;

return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(MessengerDispatchController::class)
        ->autowire()
        ->public();

    // No #[AsMessageHandler] autoconfiguration here (this microkernel does no resource-based service
    // discovery): tagged manually instead.
    $container->services()
        ->set(DispatchedJobHandler::class)
        ->autowire()
        ->tag('messenger.message_handler');
};
