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

use IQ2i\VigieBundle\Messenger\ActivityContextMiddleware;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

// Imported only when iq2i_vigie.messenger.enabled is true, so symfony/messenger's classes referenced
// here are always installed. Not tagged "messenger.middleware": that tag doesn't auto-attach a
// middleware to any bus. Reference this service id directly under
// framework.messenger.buses.<bus>.middleware, see doc/recording.md#recording-from-a-worker.
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $middleware = $services->set('iq2i_vigie.messenger.activity_context', ActivityContextMiddleware::class)
        ->arg('$requestStack', service(RequestStack::class))
        ->tag('vigie.activity_processor')
        ->tag('kernel.reset', ['method' => 'reset']);

    // Bound explicitly: an unset argument would make the container try to autoload the optional package's type.
    $middleware->arg(
        '$tokenStorage',
        interface_exists(TokenStorageInterface::class) ? service('security.token_storage')->nullOnInvalid() : null,
    );
};
