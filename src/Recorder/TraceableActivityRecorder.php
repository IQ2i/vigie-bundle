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

namespace IQ2i\VigieBundle\Recorder;

use Symfony\Contracts\Service\ResetInterface;

/**
 * @internal registered only when the profiler is active (see
 * config/services_profiler.php), for VigieDataCollector to read in
 * lateCollect()
 */
final class TraceableActivityRecorder implements RecordingObserverInterface, ResetInterface
{
    /**
     * @var list<Recording>
     */
    private array $trace = [];

    public function observe(Recording $recording): void
    {
        $this->trace[] = $recording;
    }

    /**
     * @return list<Recording>
     */
    public function getTrace(): array
    {
        return $this->trace;
    }

    public function reset(): void
    {
        $this->trace = [];
    }
}
