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

use IQ2i\VigieBundle\EventSubscriber\HttpActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\RequestIdSubscriber;
use IQ2i\VigieBundle\EventSubscriber\SecurityActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use IQ2i\VigieBundle\Http\TrackingDecider;
use IQ2i\VigieBundle\Monolog\EcsFormatter;
use IQ2i\VigieBundle\Processor\RequestContextProcessor;
use IQ2i\VigieBundle\Processor\TokenProcessor;
use IQ2i\VigieBundle\Recorder\ActivityRecorder;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Recorder\ActivityRedactor;
use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\QueryNormalizer;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Security\RecordingCsrfTokenManager;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    // Most arguments below are placeholders, overridden by
    // IQ2iVigieBundle::loadExtension() once iq2i_vigie.* is processed — see
    // the config key noted at each site.

    // Referenceable by id from a project's own monolog.yaml
    // ("formatter: 'iq2i_vigie.formatter.ecs'") when iq2i_vigie.output.handlers
    // is set — see doc/storage.md.
    $services->set('iq2i_vigie.formatter.ecs', EcsFormatter::class);

    // record.hash_secret; defaults to %kernel.secret%.
    $services->set(Pseudonymizer::class)
        ->arg('$secret', param('kernel.secret'));

    // record.*
    $services->set(RecordingOptions::class);

    $services->set(ActivityRedactor::class)
        ->arg('$options', service(RecordingOptions::class))
        ->arg('$pseudonymizer', service(Pseudonymizer::class));

    $services->set(QueryNormalizer::class)
        ->arg('$options', service(RecordingOptions::class))
        ->arg('$pseudonymizer', service(Pseudonymizer::class));

    $requestContextProcessor = $services->set(RequestContextProcessor::class)
        ->arg('$clock', service(ClockInterface::class))
        ->tag('vigie.activity_processor')
        ->tag('kernel.event_subscriber')
        ->tag('kernel.reset', ['method' => 'reset']);

    // Bound explicitly either way, rather than left unset for the
    // constructor's own default: an unset argument makes the container
    // reflect the parameter's type to resolve it, which would try to
    // autoload TokenStorageInterface even when symfony/security-core isn't
    // installed.
    $requestContextProcessor->arg(
        '$tokenStorage',
        interface_exists(TokenStorageInterface::class) ? service('security.token_storage')->nullOnInvalid() : null,
    );

    if (interface_exists(TokenStorageInterface::class)) {
        $services->set(TokenProcessor::class)
            ->arg('$tokenStorage', service('security.token_storage')->nullOnInvalid())
            ->tag('vigie.activity_processor');
    }

    $services->set(ActivityRecorder::class)
        ->arg('$storage', service(ActivityStorageInterface::class))
        ->arg('$redactor', service(ActivityRedactor::class))
        ->arg('$dispatcher', service('event_dispatcher')->nullOnInvalid())
        ->arg('$processors', tagged_iterator('vigie.activity_processor'))
        ->arg('$clock', service(ClockInterface::class))
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('monolog.logger', ['channel' => 'vigie']);

    $services->alias(ActivityRecorderInterface::class, ActivityRecorder::class);

    // http.request_id_header; removed entirely when http is disabled.
    $services->set(RequestIdSubscriber::class)
        ->arg('$requestIdHeader', null)
        ->tag('kernel.event_subscriber');

    // http.ignored_paths/recorded_paths
    $services->set(TrackingDecider::class)
        ->arg('$deciders', tagged_iterator('vigie.activity_decider'))
        ->arg('$ignoredPaths', [])
        ->arg('$recordedPaths', []);

    $services->set(TrackingAttributeSubscriber::class)
        ->tag('kernel.event_subscriber');

    $services->set(HttpActivitySubscriber::class)
        ->arg('$recorder', service(ActivityRecorderInterface::class))
        ->arg('$clock', service(ClockInterface::class))
        ->arg('$tokenStorage', service('security.token_storage')->nullOnInvalid())
        ->arg('$queryString', false)
        ->arg('$routeParams', false)
        ->arg('$decider', service(TrackingDecider::class))
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('kernel.event_subscriber')
        ->tag('kernel.reset', ['method' => 'reset'])
        ->tag('monolog.logger', ['channel' => 'vigie']);

    if (class_exists(LoginSuccessEvent::class)) {
        // security.record_non_interactive, security.record_access_denied
        $services->set(SecurityActivitySubscriber::class)
            ->arg('$recorder', service(ActivityRecorderInterface::class))
            ->arg('$clock', service(ClockInterface::class))
            ->arg('$tokenStorage', service('security.token_storage')->nullOnInvalid())
            ->arg('$recordNonInteractive', true)
            ->arg('$recordAccessDenied', true)
            ->arg('$logger', service('logger')->nullOnInvalid())
            ->tag('kernel.event_subscriber')
            ->tag('monolog.logger', ['channel' => 'vigie']);
    }

    if (interface_exists(CsrfTokenManagerInterface::class)) {
        // security.record_csrf_failure
        $services->set(RecordingCsrfTokenManager::class)
            // Negative priority on purpose: DecoratorServicePass processes
            // the highest decoration priority first (SplPriorityQueue
            // extracts highest first), and each later decorator wraps the
            // chain built so far — so the *lowest* priority ends up
            // outermost. SameOriginCsrfTokenManager decorates at the
            // default priority (0) and answers isTokenValid() itself for
            // framework.csrf_protection.stateless_token_ids; wrapping it is
            // the only way to see those calls too.
            ->decorate('security.csrf.token_manager', null, -10, ContainerInterface::IGNORE_ON_INVALID_REFERENCE)
            ->arg('$inner', service('.inner'))
            ->arg('$recorder', service(ActivityRecorderInterface::class))
            ->arg('$logger', service('logger')->nullOnInvalid())
            ->tag('monolog.logger', ['channel' => 'vigie']);
    }
};
