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

use IQ2i\VigieBundle\Model\Activity;

/**
 * @internal what ActivityRecorder::record() did with one activity, reported
 * to RecordingObserverInterface
 */
final readonly class Recording
{
    public function __construct(
        public Activity $submitted,
        public ?Activity $final,
        public RecordingOutcome $outcome,
    ) {
    }
}
