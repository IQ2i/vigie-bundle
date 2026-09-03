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

namespace IQ2i\VigieBundle\Model;

use IQ2i\VigieBundle\Uid\UidGenerator;

/**
 * An immutable, transport-friendly representation of a tracked activity.
 */
final readonly class Activity
{
    public ActivityType $type;
    public \DateTimeImmutable $occurredAt;
    public ?string $action;
    public ?string $userIdentifier;
    public ?string $ipAddress;
    public ?string $userAgent;
    public ?string $method;
    public ?string $uri;
    public ?string $route;
    public ?int $statusCode;
    public ?string $firewall;
    public ?string $sessionId;
    public ?string $requestId;
    public ?Subject $subject;
    public ?string $remediation;

    /**
     * @var array<string, scalar|null>
     */
    public array $context;

    /**
     * Minted once and carried unchanged through every wither.
     */
    public string $eventId;

    /**
     * @param array<string, mixed> $context any entry whose value is not a
     *                                      scalar or null is silently
     *                                      dropped — recording must never
     *                                      throw over a caller's own
     *                                      context payload
     */
    public function __construct(
        ActivityType $type,
        \DateTimeImmutable $occurredAt,
        ?string $action = null,
        ?string $userIdentifier = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?string $method = null,
        ?string $uri = null,
        ?string $route = null,
        ?int $statusCode = null,
        ?string $firewall = null,
        ?string $sessionId = null,
        ?string $requestId = null,
        ?Subject $subject = null,
        array $context = [],
        ?string $eventId = null,
        ?string $remediation = null,
    ) {
        $this->type = $type;
        $this->occurredAt = $occurredAt;
        // An empty string (a NullToken's identifier, an unmatched route) must group with "no value", not with itself as a bogus subject.
        $this->action = '' !== $action ? $action : null;
        $this->userIdentifier = '' !== $userIdentifier ? $userIdentifier : null;
        $this->ipAddress = '' !== $ipAddress ? $ipAddress : null;
        $this->userAgent = '' !== $userAgent ? $userAgent : null;
        $this->method = $method;
        $this->uri = $uri;
        $this->route = '' !== $route ? $route : null;
        $this->statusCode = $statusCode;

        /** @var array<string, scalar|null> $context */
        $context = array_filter($context, static fn (mixed $value): bool => \is_scalar($value) || null === $value);
        $this->context = $context;

        $this->firewall = '' !== $firewall ? $firewall : null;
        $this->sessionId = '' !== $sessionId ? $sessionId : null;
        $this->requestId = '' !== $requestId ? $requestId : null;
        $this->subject = $subject;
        $this->eventId = null !== $eventId && '' !== $eventId ? $eventId : UidGenerator::generate();
        $this->remediation = '' !== $remediation ? $remediation : null;
    }

    /**
     * @param array<string, scalar|null> $context
     */
    public static function httpRequest(
        \DateTimeImmutable $occurredAt,
        string $method,
        string $uri,
        int $statusCode,
        ?string $route = null,
        ?string $userIdentifier = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        array $context = [],
        ?string $firewall = null,
        ?string $sessionId = null,
        ?string $requestId = null,
        ?Subject $subject = null,
    ): self {
        return new self(
            type: ActivityType::HttpRequest,
            occurredAt: $occurredAt,
            userIdentifier: $userIdentifier,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            method: $method,
            uri: $uri,
            route: $route,
            statusCode: $statusCode,
            firewall: $firewall,
            sessionId: $sessionId,
            requestId: $requestId,
            subject: $subject,
            context: $context,
        );
    }

    /**
     * @param array<string, scalar|null> $context
     *
     * @throws \InvalidArgumentException if $type is Custom or HttpRequest —
     *                                   use custom() or httpRequest() instead
     */
    public static function security(
        ActivityType $type,
        \DateTimeImmutable $occurredAt,
        ?string $userIdentifier = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        array $context = [],
        ?string $firewall = null,
        ?string $sessionId = null,
        ?string $requestId = null,
        ?Subject $subject = null,
    ): self {
        if (ActivityType::Custom === $type || ActivityType::HttpRequest === $type) {
            throw new \InvalidArgumentException(\sprintf('Activity::security() does not accept "%s" — use Activity::custom() or Activity::httpRequest() instead.', $type->value));
        }

        return new self(
            type: $type,
            occurredAt: $occurredAt,
            userIdentifier: $userIdentifier,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            firewall: $firewall,
            sessionId: $sessionId,
            requestId: $requestId,
            subject: $subject,
            context: $context,
        );
    }

    /**
     * A business-defined activity that doesn't fit the two shapes above —
     * an export, a payment, a role change. $action is a short, indexed,
     * free-form label (by convention `^[a-z0-9_.:-]+$`, e.g.
     * "export.completed") that a reader can filter on directly instead of
     * relying on an unindexed context key.
     *
     * @param array<string, scalar|null> $context
     */
    public static function custom(
        string $action,
        \DateTimeImmutable $occurredAt,
        ?string $userIdentifier = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        array $context = [],
        ?string $firewall = null,
        ?string $sessionId = null,
        ?string $requestId = null,
        ?Subject $subject = null,
    ): self {
        return new self(
            type: ActivityType::Custom,
            occurredAt: $occurredAt,
            action: $action,
            userIdentifier: $userIdentifier,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            firewall: $firewall,
            sessionId: $sessionId,
            requestId: $requestId,
            subject: $subject,
            context: $context,
        );
    }

    public function withAction(?string $action): self
    {
        return $this->with(['action' => $action]);
    }

    public function withUserIdentifier(?string $userIdentifier): self
    {
        return $this->with(['userIdentifier' => $userIdentifier]);
    }

    public function withIpAddress(?string $ipAddress): self
    {
        return $this->with(['ipAddress' => $ipAddress]);
    }

    public function withUserAgent(?string $userAgent): self
    {
        return $this->with(['userAgent' => $userAgent]);
    }

    public function withMethod(?string $method): self
    {
        return $this->with(['method' => $method]);
    }

    public function withUri(?string $uri): self
    {
        return $this->with(['uri' => $uri]);
    }

    public function withRoute(?string $route): self
    {
        return $this->with(['route' => $route]);
    }

    public function withStatusCode(?int $statusCode): self
    {
        return $this->with(['statusCode' => $statusCode]);
    }

    public function withFirewall(?string $firewall): self
    {
        return $this->with(['firewall' => $firewall]);
    }

    public function withSessionId(?string $sessionId): self
    {
        return $this->with(['sessionId' => $sessionId]);
    }

    public function withRequestId(?string $requestId): self
    {
        return $this->with(['requestId' => $requestId]);
    }

    public function withSubject(?Subject $subject): self
    {
        return $this->with(['subject' => $subject]);
    }

    /**
     * @param array<string, scalar|null> $context replaces the whole context
     */
    public function withContext(array $context): self
    {
        return $this->with(['context' => $context]);
    }

    /**
     * @param array<string, scalar|null> $context merged onto the existing
     *                                            context, overwriting keys
     *                                            it shares with it
     */
    public function withAddedContext(array $context): self
    {
        return $this->with(['context' => array_replace($this->context, $context)]);
    }

    public function withEventId(string $eventId): self
    {
        return $this->with(['eventId' => $eventId]);
    }

    public function withRemediation(?string $remediation): self
    {
        return $this->with(['remediation' => $remediation]);
    }

    /**
     * @param array{
     *     type?: ActivityType,
     *     occurredAt?: \DateTimeImmutable,
     *     action?: ?string,
     *     userIdentifier?: ?string,
     *     ipAddress?: ?string,
     *     userAgent?: ?string,
     *     method?: ?string,
     *     uri?: ?string,
     *     route?: ?string,
     *     statusCode?: ?int,
     *     firewall?: ?string,
     *     sessionId?: ?string,
     *     requestId?: ?string,
     *     subject?: ?Subject,
     *     context?: array<string, scalar|null>,
     *     eventId?: ?string,
     *     remediation?: ?string,
     * } $changes
     */
    private function with(array $changes): self
    {
        $args = [
            'type' => $this->type,
            'occurredAt' => $this->occurredAt,
            'action' => $this->action,
            'userIdentifier' => $this->userIdentifier,
            'ipAddress' => $this->ipAddress,
            'userAgent' => $this->userAgent,
            'method' => $this->method,
            'uri' => $this->uri,
            'route' => $this->route,
            'statusCode' => $this->statusCode,
            'firewall' => $this->firewall,
            'sessionId' => $this->sessionId,
            'requestId' => $this->requestId,
            'subject' => $this->subject,
            'context' => $this->context,
            'eventId' => $this->eventId,
            'remediation' => $this->remediation,
            ...$changes,
        ];

        return new self(...$args);
    }
}
