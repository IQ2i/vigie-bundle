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

namespace IQ2i\VigieBundle\DataCollector;

use IQ2i\VigieBundle\Http\TrackingDecision;
use IQ2i\VigieBundle\Http\TrackingSource;
use IQ2i\VigieBundle\Recorder\Recording;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Recorder\TraceableActivityRecorder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\HttpKernel\DataCollector\LateDataCollectorInterface;

/**
 * @internal registered only in debug mode with symfony/web-profiler-bundle installed
 *
 * Answers "was this request recorded, and why (not)?" and lists every
 * activity ActivityRecorder processed. Implements LateDataCollectorInterface
 * since HttpActivitySubscriber only writes its HTTP request activity on
 * kernel.terminate, after collect() already ran.
 */
final class VigieDataCollector extends DataCollector implements LateDataCollectorInterface
{
    /**
     * @param list<string> $recordedPaths
     * @param list<string> $ignoredPaths
     */
    public function __construct(
        private readonly ?TraceableActivityRecorder $tracer,
        private readonly bool $httpEnabled,
        private readonly array $recordedPaths,
        private readonly array $ignoredPaths,
        private readonly RecordingOptions $recordingOptions,
    ) {
    }

    public function collect(Request $request, Response $response, ?\Throwable $exception = null): void
    {
        $decision = $this->httpEnabled
            ? $request->attributes->get(TrackingDecision::ATTRIBUTE)
            : new TrackingDecision(false, TrackingSource::HttpDisabled);

        if (!$decision instanceof TrackingDecision) {
            $decision = new TrackingDecision(false, TrackingSource::Default);
        }

        $this->data = [
            'decision' => [
                'recorded' => $decision->recorded,
                'source' => $decision->source->name,
                'detail' => $decision->detail,
            ],
            'activities' => [],
            'config' => [
                'http_enabled' => $this->httpEnabled,
                'recorded_paths' => $this->recordedPaths,
                'ignored_paths' => $this->ignoredPaths,
                'ip_address_mode' => $this->recordingOptions->ipAddressMode->value,
                'user_identifier_mode' => $this->recordingOptions->userIdentifierMode->value,
            ],
            'count' => 0,
        ];
    }

    public function lateCollect(): void
    {
        $trace = $this->tracer?->getTrace() ?? [];

        $activities = array_map(function (Recording $recording): array {
            $activity = $recording->final ?? $recording->submitted;

            return [
                'type' => $activity->type->value,
                'action' => $activity->action,
                'user' => $activity->userIdentifier,
                'ip' => $activity->ipAddress,
                'route' => $activity->route,
                'uri' => $activity->uri,
                'status' => $activity->statusCode,
                'subject' => null !== $activity->subject ? \sprintf('%s:%s', $activity->subject->type, $activity->subject->id) : null,
                'context' => $this->cloneVar($activity->context),
                'outcome' => $recording->outcome->name,
            ];
        }, $trace);

        $this->data['activities'] = $activities;
        $this->data['count'] = \count($activities);
    }

    public function getName(): string
    {
        return 'vigie';
    }

    /**
     * @return array{recorded: bool, source: string, detail: ?string}
     */
    public function getDecision(): array
    {
        /** @var array{recorded: bool, source: string, detail: ?string} $decision */
        $decision = $this->data['decision'];

        return $decision;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getActivities(): array
    {
        /** @var list<array<string, mixed>> $activities */
        $activities = $this->data['activities'];

        return $activities;
    }

    /**
     * @return array<string, mixed>
     */
    public function getConfig(): array
    {
        /** @var array<string, mixed> $config */
        $config = $this->data['config'];

        return $config;
    }

    public function getCount(): int
    {
        /** @var int $count */
        $count = $this->data['count'];

        return $count;
    }
}
