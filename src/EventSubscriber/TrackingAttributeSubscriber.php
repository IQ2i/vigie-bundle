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

namespace IQ2i\VigieBundle\EventSubscriber;

use IQ2i\VigieBundle\Attribute\Track;
use IQ2i\VigieBundle\Attribute\Untrack;
use IQ2i\VigieBundle\Model\Subject;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Reads #[Track]/#[Untrack] off the resolved controller (see Track/Untrack
 * for the combination rules) and stamps the verdict, the action and the
 * subject on request attributes read back by HttpActivitySubscriber.
 *
 * Uses its own reflection instead of ControllerEvent::getAttributes(), which merges class and method attributes without telling them apart.
 */
final class TrackingAttributeSubscriber implements EventSubscriberInterface
{
    public const ATTRIBUTE = '_vigie_track';
    public const ACTION_ATTRIBUTE = '_vigie_track_action';
    public const SUBJECT_ATTRIBUTE = '_vigie_track_subject';

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController',
        ];
    }

    public function onKernelController(ControllerEvent $event): void
    {
        $controller = $event->getController();

        [$classAttributes, $methodAttributes] = match (true) {
            \is_array($controller) => [
                self::attributesOf(new \ReflectionClass($controller[0])),
                self::attributesOf(new \ReflectionClass($controller[0]), $controller[1]),
            ],
            $controller instanceof \Closure => [
                [],
                self::attributesOf(new \ReflectionFunction($controller)),
            ],
            \is_object($controller) => [
                self::attributesOf(new \ReflectionClass($controller)),
                self::attributesOf(new \ReflectionClass($controller), '__invoke'),
            ],
            default => [[], []],
        };

        $verdict = self::resolve($methodAttributes) ?? self::resolve($classAttributes);

        if (null !== $verdict) {
            $event->getRequest()->attributes->set(self::ATTRIBUTE, $verdict);
        }

        $classAction = self::firstTrack($classAttributes)?->action;
        $methodAction = self::firstTrack($methodAttributes)?->action;

        $action = match (true) {
            null !== $classAction && null !== $methodAction => rtrim($classAction, '.').'.'.ltrim($methodAction, '.'),
            null !== $methodAction => $methodAction,
            default => $classAction,
        };

        if (null !== $action) {
            $event->getRequest()->attributes->set(self::ACTION_ATTRIBUTE, $action);
        }

        $track = self::firstTrack($methodAttributes) ?? self::firstTrack($classAttributes);

        if (null !== $track && null !== $track->subject) {
            $subject = self::resolveSubject($event, $track->subject, $track->subjectParam);

            if (null !== $subject) {
                $event->getRequest()->attributes->set(self::SUBJECT_ATTRIBUTE, $subject);
            }
        }
    }

    private static function resolveSubject(ControllerEvent $event, string $type, string $param): ?Subject
    {
        /** @var array<string, mixed> $routeParams */
        $routeParams = $event->getRequest()->attributes->get('_route_params', []);
        $value = $routeParams[$param] ?? null;

        return \is_scalar($value) ? new Subject($type, (string) $value) : null;
    }

    /**
     * @template T of object
     *
     * @param \ReflectionClass<T>|\ReflectionFunction $reflection
     *
     * @return list<Track|Untrack>
     */
    private static function attributesOf(\ReflectionClass|\ReflectionFunction $reflection, ?string $method = null): array
    {
        if (null !== $method) {
            if (!$reflection instanceof \ReflectionClass || !$reflection->hasMethod($method)) {
                return [];
            }

            $reflection = $reflection->getMethod($method);
        }

        $attributes = [];

        foreach ($reflection->getAttributes(Track::class) as $attribute) {
            $attributes[] = $attribute->newInstance();
        }

        foreach ($reflection->getAttributes(Untrack::class) as $attribute) {
            $attributes[] = $attribute->newInstance();
        }

        return $attributes;
    }

    /**
     * @param list<Track|Untrack> $attributes
     */
    private static function resolve(array $attributes): ?bool
    {
        $hasTrack = self::firstTrack($attributes) instanceof Track;
        $hasUntrack = self::firstUntrack($attributes) instanceof Untrack;

        if ($hasTrack && $hasUntrack) {
            throw new \LogicException('#[Track] and #[Untrack] cannot both be applied to the same class or method.');
        }

        return match (true) {
            $hasTrack => true,
            $hasUntrack => false,
            default => null,
        };
    }

    /**
     * @param list<Track|Untrack> $attributes
     */
    private static function firstTrack(array $attributes): ?Track
    {
        foreach ($attributes as $attribute) {
            if ($attribute instanceof Track) {
                return $attribute;
            }
        }

        return null;
    }

    /**
     * @param list<Track|Untrack> $attributes
     */
    private static function firstUntrack(array $attributes): ?Untrack
    {
        foreach ($attributes as $attribute) {
            if ($attribute instanceof Untrack) {
                return $attribute;
            }
        }

        return null;
    }
}
