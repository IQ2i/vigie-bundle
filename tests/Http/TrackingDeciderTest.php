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

namespace IQ2i\VigieBundle\Tests\Http;

use IQ2i\VigieBundle\Decider\ActivityDeciderInterface;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use IQ2i\VigieBundle\Http\TrackingDecider;
use IQ2i\VigieBundle\Http\TrackingSource;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class TrackingDeciderTest extends TestCase
{
    public function testNothingIsRecordedByDefault(): void
    {
        $decision = (new TrackingDecider())->decide(Request::create('/dashboard'));

        self::assertFalse($decision->recorded);
        self::assertSame(TrackingSource::Default, $decision->source);
    }

    public function testAttributeWinsOverTheDefault(): void
    {
        $request = Request::create('/dashboard');
        $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, true);

        $decision = (new TrackingDecider())->decide($request);

        self::assertTrue($decision->recorded);
        self::assertSame(TrackingSource::Attribute, $decision->source);
    }

    public function testIgnoredPathWinsOverRecordedPath(): void
    {
        $decider = new TrackingDecider(ignoredPaths: ['^/_'], recordedPaths: ['^/']);

        $decision = $decider->decide(Request::create('/_profiler/abc123'));

        self::assertFalse($decision->recorded);
        self::assertSame(TrackingSource::IgnoredPath, $decision->source);
        self::assertSame('^/_', $decision->detail);
    }

    public function testRecordedPathEnablesMatchingPaths(): void
    {
        $decider = new TrackingDecider(recordedPaths: ['^/admin']);

        self::assertFalse($decider->decide(Request::create('/front'))->recorded);

        $decision = $decider->decide(Request::create('/admin/dashboard'));
        self::assertTrue($decision->recorded);
        self::assertSame(TrackingSource::RecordedPath, $decision->source);
        self::assertSame('^/admin', $decision->detail);
    }

    public function testUntrackAttributeBypassesRecordedPaths(): void
    {
        $decider = new TrackingDecider(recordedPaths: ['^/']);

        $request = Request::create('/dashboard');
        $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, false);

        self::assertFalse($decider->decide($request)->recorded);
    }

    public function testTrackAttributeBypassesIgnoredAndRecordedPaths(): void
    {
        $decider = new TrackingDecider(ignoredPaths: ['^/_'], recordedPaths: ['^/admin']);

        $request = Request::create('/_profiler/abc123');
        $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, true);

        self::assertTrue($decider->decide($request)->recorded);
    }

    public function testDeciderVerdictWinsOverEverythingElse(): void
    {
        $inner = $this->createMock(ActivityDeciderInterface::class);
        $inner->method('decide')->willReturn(true);

        $decider = new TrackingDecider([$inner], ignoredPaths: ['^/_']);

        $request = Request::create('/_profiler/abc123');
        $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, false);

        $decision = $decider->decide($request);

        self::assertTrue($decision->recorded);
        self::assertSame(TrackingSource::Decider, $decision->source);
        self::assertSame($inner::class, $decision->detail);
    }

    public function testDeciderAbstentionFallsBackToTheAttribute(): void
    {
        $inner = $this->createMock(ActivityDeciderInterface::class);
        $inner->method('decide')->willReturn(null);

        $decider = new TrackingDecider([$inner]);

        $request = Request::create('/dashboard');
        $request->attributes->set(TrackingAttributeSubscriber::ATTRIBUTE, false);

        self::assertFalse($decider->decide($request)->recorded);
    }

    public function testFirstNonNullVerdictAmongSeveralDecidersWins(): void
    {
        $abstaining = $this->createMock(ActivityDeciderInterface::class);
        $abstaining->method('decide')->willReturn(null);

        $deciding = $this->createMock(ActivityDeciderInterface::class);
        $deciding->method('decide')->willReturn(true);

        $decider = new TrackingDecider([$abstaining, $deciding]);

        $decision = $decider->decide(Request::create('/dashboard'));

        self::assertSame(TrackingSource::Decider, $decision->source);
        self::assertSame($deciding::class, $decision->detail);
    }
}
