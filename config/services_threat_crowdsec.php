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

use IQ2i\VigieBundle\Threat\CrowdSec\CrowdSecProvider;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

// Imported by IQ2iVigieBundle::loadExtension() only when threat.provider is
// "crowdsec" AND symfony/http-client is installed — checked before this file
// is ever imported, so referencing HttpClient/HttpClientInterface here is
// always safe. Most arguments below are placeholders, overridden by
// loadThreatExtension().
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    // A scoped client, its base URI/timeout overridden by loadExtension()
    // from iq2i_vigie.threat.crowdsec.url/timeout — skipped entirely, in
    // favor of the service named by threat.crowdsec.http_client, when one
    // is configured.
    $services->set('iq2i_vigie.threat.crowdsec.http_client', HttpClientInterface::class)
        ->factory([HttpClient::class, 'createForBaseUri'])
        ->args(['http://127.0.0.1:8080', ['timeout' => 5.0]]);

    // threat.crowdsec.*
    $services->set(CrowdSecProvider::class)
        ->arg('$client', service('iq2i_vigie.threat.crowdsec.http_client'))
        ->arg('$apiKey', '')
        ->arg('$scopes', ['Ip', 'Range'])
        ->arg('$origins', [])
        ->arg('$scenariosContaining', [])
        ->arg('$clock', service(ClockInterface::class))
        ->arg('$logger', service('logger')->nullOnInvalid())
        ->tag('monolog.logger', ['channel' => 'vigie']);
};
