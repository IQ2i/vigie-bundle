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

use IQ2i\VigieBundle\Event\ActivityRecording;
use IQ2i\VigieBundle\Model\Activity;
use IQ2i\VigieBundle\Model\ActivityType;
use IQ2i\VigieBundle\Model\Subject;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;

/**
 * Records activities directly through the storage.
 *
 * A failure here is never allowed to break the caller: tracking activity
 * must not be able to turn a successful request or a successful login into
 * a 500, so any exception is logged and swallowed rather than propagated.
 */
final readonly class ActivityRecorder implements ActivityRecorderInterface
{
    /**
     * @param iterable<ActivityProcessorInterface> $processors
     */
    public function __construct(
        private ActivityStorageInterface $storage,
        private ActivityRedactor $redactor,
        private ?EventDispatcherInterface $dispatcher = null,
        private iterable $processors = [],
        private ClockInterface $clock = new Clock(),
        private ?RecordingObserverInterface $observer = null,
        private ?LoggerInterface $logger = null,
    ) {
    }

    public function record(Activity $activity): void
    {
        $submitted = $activity;

        try {
            // Processors run first, filling in whatever they know how to
            // find (the current request, the current token) — so what they
            // add is still subject to record.* like everything else.
            $activity = $this->process($activity);

            // Redaction runs right after processors: a listener below, or a
            // consumer of the ActivityRecording event, must never see a
            // value the application asked record.* to drop or pseudonymize.
            $activity = $this->redactor->redact($activity);

            if (null !== $this->dispatcher) {
                $activity = $this->enrich($this->dispatcher, $activity);

                if (null === $activity) {
                    $this->observe($submitted, null, RecordingOutcome::Cancelled);

                    return;
                }
            }

            $this->storage->store($activity);
            $this->observe($submitted, $activity, RecordingOutcome::Stored);
        } catch (\Throwable $e) {
            $this->observe($submitted, null, RecordingOutcome::Failed);

            $this->logger?->error('Vigie could not record an activity of type "{type}": {message}', [
                'type' => $submitted->type->value,
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);
        }
    }

    /**
     * An observer that throws never affects recording — it already happened by the time this runs.
     */
    private function observe(Activity $submitted, ?Activity $final, RecordingOutcome $outcome): void
    {
        try {
            $this->observer?->observe(new Recording($submitted, $final, $outcome));
        } catch (\Throwable) {
        }
    }

    /**
     * @param array<string, scalar|null> $context
     */
    public function custom(string $action, array $context = [], ?Subject $subject = null): void
    {
        $this->record(Activity::custom($action, $this->clock->now(), context: $context, subject: $subject));
    }

    public function security(ActivityType $type, ?string $userIdentifier = null, array $context = [], ?Subject $subject = null): void
    {
        $this->record(Activity::security($type, $this->clock->now(), $userIdentifier, context: $context, subject: $subject));
    }

    /**
     * A processor that throws never loses the activity — it is still recorded with whatever it would have added missing.
     */
    private function process(Activity $activity): Activity
    {
        foreach ($this->processors as $processor) {
            try {
                $activity = $processor($activity);
            } catch (\Throwable $e) {
                $this->logger?->warning('An activity processor "{processor}" failed while recording an activity of type "{type}": {message}', [
                    'processor' => $processor::class,
                    'type' => $activity->type->value,
                    'message' => $e->getMessage(),
                    'exception' => $e,
                ]);
            }
        }

        return $activity;
    }

    /**
     * @return ?Activity null when a listener vetoed the recording
     */
    private function enrich(EventDispatcherInterface $dispatcher, Activity $activity): ?Activity
    {
        $event = new ActivityRecording($activity);

        try {
            $dispatcher->dispatch($event);
        } catch (\Throwable $e) {
            $this->logger?->warning('An "{event}" listener failed while recording an activity of type "{type}": {message}', [
                'event' => ActivityRecording::class,
                'type' => $activity->type->value,
                'message' => $e->getMessage(),
                'exception' => $e,
            ]);

            return $activity;
        }

        return $event->isCancelled() ? null : $event->getActivity();
    }
}
