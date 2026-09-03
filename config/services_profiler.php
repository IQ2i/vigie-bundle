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

use IQ2i\VigieBundle\DataCollector\VigieDataCollector;
use IQ2i\VigieBundle\Recorder\ActivityRecorder;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Recorder\TraceableActivityRecorder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Loaded only when kernel.debug is true and symfony/web-profiler-bundle is
 * installed (see IQ2iVigieBundle::loadExtension()) — costs nothing outside
 * that combination. $httpEnabled/$recordedPaths/$ignoredPaths below are
 * overridden from iq2i_vigie.http.*.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(TraceableActivityRecorder::class)
        ->tag('kernel.reset', ['method' => 'reset']);

    $container->services()
        ->get(ActivityRecorder::class)
        ->arg('$observer', service(TraceableActivityRecorder::class));

    $container->services()
        ->set(VigieDataCollector::class)
        ->arg('$tracer', service(TraceableActivityRecorder::class))
        ->arg('$httpEnabled', true)
        ->arg('$recordedPaths', [])
        ->arg('$ignoredPaths', [])
        ->arg('$recordingOptions', service(RecordingOptions::class))
        ->tag('data_collector', [
            'id' => 'vigie',
            'template' => '@IQ2iVigie/data_collector/vigie.html.twig',
            'priority' => 255,
        ]);
};
