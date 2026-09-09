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

namespace IQ2i\VigieBundle\Tests\Recorder;

use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Recorder\Recording;
use IQ2i\VigieBundle\Recorder\RecordingOutcome;
use IQ2i\VigieBundle\Recorder\TraceableActivityRecorder;
use PHPUnit\Framework\TestCase;

final class TraceableActivityRecorderTest extends TestCase
{
    public function testObserveAppendsToTheTrace(): void
    {
        $tracer = new TraceableActivityRecorder();
        $submitted = Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable());
        $recording = new Recording($submitted, $submitted, RecordingOutcome::Stored);

        $tracer->observe($recording);

        self::assertSame([$recording], $tracer->getTrace());
    }

    public function testResetClearsTheTrace(): void
    {
        $tracer = new TraceableActivityRecorder();
        $tracer->observe(new Recording(Activity::security(ActivityType::LoginSuccess, new \DateTimeImmutable()), null, RecordingOutcome::Failed));

        $tracer->reset();

        self::assertSame([], $tracer->getTrace());
    }
}
