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

namespace IQ2i\VigieBundle\Tests\DataCollector;

use IQ2i\VigieBundle\DataCollector\VigieDataCollector;
use IQ2i\VigieBundle\Http\TrackingDecision;
use IQ2i\VigieBundle\Http\TrackingSource;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\Recording;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Recorder\RecordingOutcome;
use IQ2i\VigieBundle\Recorder\TraceableActivityRecorder;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

final class VigieDataCollectorTest extends TestCase
{
    public function testCollectReadsTheDecisionStampedOnTheRequest(): void
    {
        $request = Request::create('/admin');
        $request->attributes->set('_vigie_decision', new TrackingDecision(true, TrackingSource::Attribute, 'App\\Controller\\AdminController::delete()'));

        $collector = new VigieDataCollector(null, true, ['^/admin'], [], new RecordingOptions());
        $collector->collect($request, new Response());
        $collector->lateCollect();

        self::assertSame([
            'recorded' => true,
            'source' => 'Attribute',
            'detail' => 'App\\Controller\\AdminController::delete()',
        ], $collector->getDecision());
    }

    public function testCollectReportsHttpDisabledWithoutConsultingTheRequest(): void
    {
        $collector = new VigieDataCollector(null, false, [], [], new RecordingOptions());
        $collector->collect(Request::create('/'), new Response());

        self::assertFalse($collector->getDecision()['recorded']);
        self::assertSame('HttpDisabled', $collector->getDecision()['source']);
    }

    public function testCollectFallsBackToDefaultWhenNoDecisionWasStamped(): void
    {
        $collector = new VigieDataCollector(null, true, [], [], new RecordingOptions());
        $collector->collect(Request::create('/'), new Response());

        self::assertFalse($collector->getDecision()['recorded']);
        self::assertSame('Default', $collector->getDecision()['source']);
    }

    public function testLateCollectReadsTheTracersTrace(): void
    {
        $tracer = new TraceableActivityRecorder();

        $submitted = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable(), userIdentifier: 'jane.doe');
        $final = $submitted->withIpAddress('203.0.113.0');
        $tracer->observe(new Recording($submitted, $final, RecordingOutcome::Stored));

        $failedSubmission = Activity::security(ActivityType::LoginFailure, new \DateTimeImmutable());
        $tracer->observe(new Recording($failedSubmission, null, RecordingOutcome::Failed));

        $collector = new VigieDataCollector($tracer, true, [], [], new RecordingOptions());
        $collector->collect(Request::create('/'), new Response());
        $collector->lateCollect();

        self::assertSame(2, $collector->getCount());

        $activities = $collector->getActivities();
        self::assertSame('login_success', $activities[0]['type']);
        self::assertSame('jane.doe', $activities[0]['user']);
        self::assertSame('203.0.113.0', $activities[0]['ip']);
        self::assertSame('Stored', $activities[0]['outcome']);

        self::assertSame('login_failure', $activities[1]['type']);
        self::assertSame('Failed', $activities[1]['outcome']);
    }

    public function testLateCollectIsANoOpWithoutATracer(): void
    {
        $collector = new VigieDataCollector(null, true, [], [], new RecordingOptions());
        $collector->collect(Request::create('/'), new Response());
        $collector->lateCollect();

        self::assertSame(0, $collector->getCount());
        self::assertSame([], $collector->getActivities());
    }

    public function testGetConfigExposesRecordModesAndHttpSettings(): void
    {
        $collector = new VigieDataCollector(null, true, ['^/admin'], ['^/_'], new RecordingOptions(ipAddress: 'anonymize', userIdentifier: 'hash'));
        $collector->collect(Request::create('/'), new Response());

        self::assertSame([
            'http_enabled' => true,
            'recorded_paths' => ['^/admin'],
            'ignored_paths' => ['^/_'],
            'ip_address_mode' => 'anonymize',
            'user_identifier_mode' => 'hash',
        ], $collector->getConfig());
    }

    public function testGetName(): void
    {
        $collector = new VigieDataCollector(null, true, [], [], new RecordingOptions());

        self::assertSame('vigie', $collector->getName());
    }
}
