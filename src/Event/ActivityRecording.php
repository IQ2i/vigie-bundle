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

namespace IQ2i\VigieBundle\Event;

use IQ2i\VigieBundle\Model\Activity;

/**
 * Dispatched by ActivityRecorder right before an activity is stored —
 * after `record.*` redaction has already run, so a listener never sees a
 * value the application asked to have dropped or pseudonymized.
 *
 * A listener can enrich the activity's context with business data (tenant,
 * plan, amount — anything worth correlating a later read against) or veto
 * the recording entirely with cancel(): a veto, not propagation control —
 * every listener still runs and can still observe the activity.
 */
final class ActivityRecording
{
    private bool $cancelled = false;

    public function __construct(
        private Activity $activity,
    ) {
    }

    public function getActivity(): Activity
    {
        return $this->activity;
    }

    public function setActivity(Activity $activity): void
    {
        $this->activity = $activity;
    }

    /**
     * @return array<string, scalar|null>
     */
    public function getContext(): array
    {
        return $this->activity->context;
    }

    /**
     * @param array<string, scalar|null> $context replaces the whole context
     */
    public function setContext(array $context): void
    {
        $this->activity = $this->activity->withContext($context);
    }

    public function addContext(string $key, string|int|float|bool|null $value): void
    {
        $this->activity = $this->activity->withAddedContext([$key => $value]);
    }

    /**
     * Vetoes this activity: it is discarded, never reaching storage.
     * Other listeners still run and can still observe it.
     */
    public function cancel(): void
    {
        $this->cancelled = true;
    }

    public function isCancelled(): bool
    {
        return $this->cancelled;
    }
}
