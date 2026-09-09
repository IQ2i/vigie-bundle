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

namespace IQ2i\VigieBundle\Http;

use IQ2i\VigieBundle\Decider\ActivityDeciderInterface;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use Symfony\Component\HttpFoundation\Request;

/**
 * Whether an HTTP request should be recorded, and why: a tagged
 * ActivityDeciderInterface wins outright; failing that, the #[Track]/
 * #[Untrack] attribute stamped by TrackingAttributeSubscriber wins; failing
 * that, http.ignored_paths excludes a path from http.recorded_paths; failing
 * that, http.recorded_paths opts a path in; the default is to not record.
 */
final class TrackingDecider
{
    /**
     * @param iterable<ActivityDeciderInterface> $deciders
     * @param list<string>                       $ignoredPaths  regular expressions (without delimiters) matched
     *                                                          against the request path; a match is never recorded
     * @param list<string>                       $recordedPaths regular expressions (without delimiters) matched
     *                                                          against the request path; nothing is recorded unless
     *                                                          a pattern matches
     */
    public function __construct(
        private readonly iterable $deciders = [],
        private readonly array $ignoredPaths = [],
        private readonly array $recordedPaths = [],
    ) {
    }

    public function decide(Request $request): TrackingDecision
    {
        foreach ($this->deciders as $decider) {
            $verdict = $decider->decide($request);

            if (null !== $verdict) {
                return new TrackingDecision($verdict, TrackingSource::Decider, $decider::class);
            }
        }

        $tracked = $request->attributes->get(TrackingAttributeSubscriber::ATTRIBUTE);

        if (\is_bool($tracked)) {
            return new TrackingDecision($tracked, TrackingSource::Attribute);
        }

        $path = $request->getPathInfo();

        $ignoredPath = self::matchingPattern($path, $this->ignoredPaths);

        if (null !== $ignoredPath) {
            return new TrackingDecision(false, TrackingSource::IgnoredPath, $ignoredPath);
        }

        $recordedPath = self::matchingPattern($path, $this->recordedPaths);

        if (null !== $recordedPath) {
            return new TrackingDecision(true, TrackingSource::RecordedPath, $recordedPath);
        }

        return new TrackingDecision(false, TrackingSource::Default);
    }

    /**
     * @param list<string> $patterns regular expressions without delimiters
     */
    private static function matchingPattern(string $path, array $patterns): ?string
    {
        foreach ($patterns as $pattern) {
            if (preg_match('{'.$pattern.'}u', $path)) {
                return $pattern;
            }
        }

        return null;
    }
}
