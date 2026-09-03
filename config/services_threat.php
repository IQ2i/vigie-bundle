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

use IQ2i\VigieBundle\Command\ListThreatDecisionsCommand;
use IQ2i\VigieBundle\Command\SyncThreatDecisionsCommand;
use IQ2i\VigieBundle\EventSubscriber\ThreatEnforcementSubscriber;
use IQ2i\VigieBundle\Recorder\QueryNormalizer;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use IQ2i\VigieBundle\Threat\ThreatChecker;
use IQ2i\VigieBundle\Threat\ThreatCheckerInterface;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

// Imported by IQ2iVigieBundle::loadExtension() only when iq2i_vigie.threat.enabled
// is true — threat.storage is always resolved once that's the case
// (defaulting to "cache"), so ThreatDecisionStoreInterface is always a
// valid reference here. Most arguments below are placeholders, overridden
// by loadThreatExtension().
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    // threat.match.*
    $services->set(ThreatChecker::class)
        ->arg('$store', service(ThreatDecisionStoreInterface::class))
        ->arg('$normalizer', service(QueryNormalizer::class))
        ->arg('$normalizeSubject', true)
        ->arg('$maxRanges', 5000)
        ->tag('kernel.reset', ['method' => 'reset'])
        ->tag('monolog.logger', ['channel' => 'vigie']);

    $services->alias(ThreatCheckerInterface::class, ThreatChecker::class);

    // threat.enforce.*; the whole definition is removed when
    // threat.enforce.enabled is false.
    $enforcementSubscriber = $services->set(ThreatEnforcementSubscriber::class)
        ->arg('$checker', service(ThreatCheckerInterface::class))
        ->arg('$remediations', [])
        ->arg('$excludePaths', [])
        ->arg('$countryHeader', null)
        ->arg('$asnHeader', null)
        ->arg('$dispatcher', service('event_dispatcher')->nullOnInvalid())
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('kernel.event_subscriber')
        ->tag('monolog.logger', ['channel' => 'vigie']);

    // Bound explicitly either way: an unset argument would make the container try to autoload the optional package's type.
    $enforcementSubscriber->arg(
        '$tokenStorage',
        interface_exists(TokenStorageInterface::class) ? service('security.token_storage')->nullOnInvalid() : null,
    );
    $enforcementSubscriber->arg(
        '$urlGenerator',
        interface_exists(UrlGeneratorInterface::class) ? service('router')->nullOnInvalid() : null,
    );

    // $provider stays null unless threat.provider names one; the ingest
    // endpoint feeds applyBatch() directly and never needs a provider.
    $services->set(ThreatSynchronizer::class)
        ->arg('$provider', null)
        ->arg('$store', service(ThreatDecisionStoreInterface::class))
        ->arg('$dispatcher', service('event_dispatcher')->nullOnInvalid())
        ->arg('$clock', service(ClockInterface::class))
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('monolog.logger', ['channel' => 'vigie']);

    if (class_exists(Command::class)) {
        $services->set(ListThreatDecisionsCommand::class)
            ->arg('$store', service(ThreatDecisionStoreInterface::class)->nullOnInvalid())
            ->tag('console.command');

        $services->set(SyncThreatDecisionsCommand::class)
            ->arg('$synchronizer', service(ThreatSynchronizer::class))
            ->tag('console.command');
    }
};
