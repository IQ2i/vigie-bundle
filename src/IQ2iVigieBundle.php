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

namespace IQ2i\VigieBundle;

use IQ2i\VigieBundle\DataCollector\VigieDataCollector;
use IQ2i\VigieBundle\Decider\ActivityDeciderInterface;
use IQ2i\VigieBundle\EventSubscriber\HttpActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\RequestIdSubscriber;
use IQ2i\VigieBundle\EventSubscriber\SecurityActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\ThreatEnforcementSubscriber;
use IQ2i\VigieBundle\EventSubscriber\TrackingAttributeSubscriber;
use IQ2i\VigieBundle\Http\TrackingDecider;
use IQ2i\VigieBundle\Processor\ActivityProcessorInterface;
use IQ2i\VigieBundle\Recorder\Pseudonymizer;
use IQ2i\VigieBundle\Recorder\RecordingOptions;
use IQ2i\VigieBundle\Security\RecordingCsrfTokenManager;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;
use IQ2i\VigieBundle\Storage\CacheThreatDecisionStore;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Storage\InMemoryThreatDecisionStore;
use IQ2i\VigieBundle\Storage\MonologActivityStorage;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use IQ2i\VigieBundle\Threat\CrowdSec\CrowdSecProvider;
use IQ2i\VigieBundle\Threat\Ingest\IngestController;
use IQ2i\VigieBundle\Threat\ThreatChecker;
use IQ2i\VigieBundle\Threat\ThreatProviderInterface;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use Symfony\Bundle\WebProfilerBundle\WebProfilerBundle;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class IQ2iVigieBundle extends AbstractBundle
{
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);

        $container->registerForAutoconfiguration(ActivityDeciderInterface::class)
            ->addTag('vigie.activity_decider');

        $container->registerForAutoconfiguration(ActivityProcessorInterface::class)
            ->addTag('vigie.activity_processor');
    }

    public function configure(DefinitionConfigurator $definition): void
    {
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $definition->rootNode();

        $rootNode
            ->children()
                ->booleanNode('enabled')->defaultTrue()->end()
                ->scalarNode('app')
                    ->defaultNull()
                    ->info('Stamped as "app" on every recorded line (NDJSON, stream) — lets an external consumer reading several applications\' streams tell them apart. Null omits it.')
                ->end()
                ->scalarNode('env')
                    ->defaultValue('%kernel.environment%')
                    ->info('Stamped as "env" on every recorded line, the same way "app" is. Defaults to the current kernel environment.')
                ->end()
                ->scalarNode('storage')
                    ->defaultNull()
                    ->info('Service id implementing ActivityStorageInterface, or "in_memory" to use the bundle\'s in-memory test double. Defaults to "monolog": activities are logged as ECS (Elastic Common Schema) documents through a dedicated Monolog channel — see iq2i_vigie.output and doc/storage.md.')
                    ->validate()->always(self::validateServiceIdOrNull('storage'))->end()
                ->end()
                ->arrayNode('output')
                    ->addDefaultsIfNotSet()
                    ->info('Settings for the built-in Monolog storage (iq2i_vigie.storage: "monolog", the default) — see doc/storage.md.')
                    ->children()
                        ->scalarNode('path')
                            ->defaultValue('%kernel.logs_dir%/vigie.jsonl')
                            ->cannotBeEmpty()
                            ->info('Stream URL the default handler writes NDJSON to when "handlers" is empty — an absolute path, or e.g. "php://stdout" for a containerized deployment. Ignored once "handlers" is non-empty.')
                        ->end()
                        ->arrayNode('handlers')
                            ->info('Service ids implementing Monolog\Handler\HandlerInterface. Empty (the default) makes Vigie create a single StreamHandler on "path" with its own ECS formatter. Once set, Vigie never touches a listed handler\'s formatter — configure it yourself (e.g. formatter: \'iq2i_vigie.formatter.ecs\' in monolog.yaml).')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('record')
                    ->addDefaultsIfNotSet()
                    ->info('Individually toggle which fields get recorded. A field disabled here is nulled out — never merely hidden — before the activity ever reaches a storage or an ActivityRecording listener.')
                    ->children()
                        ->variableNode('ip_address')->defaultValue('anonymize')
                            ->info('true, false, or "anonymize" (the default) to mask the host part (IpUtils::anonymize — /24 for IPv4, /64 for IPv6) instead of dropping it. Set to true for the full, unmasked address.')
                            ->validate()
                                ->ifTrue(static fn (mixed $v): bool => !\in_array($v, [true, false, 'anonymize'], true))
                                ->thenInvalid('iq2i_vigie.record.ip_address must be true, false, or "anonymize", got %s.')
                            ->end()
                        ->end()
                        ->booleanNode('user_agent')->defaultTrue()->end()
                        ->variableNode('user_identifier')->defaultTrue()
                            ->info('true, false, or "hash" to HMAC the identifier (record.hash_secret) instead of dropping it.')
                            ->validate()
                                ->ifTrue(static fn (mixed $v): bool => !\in_array($v, [true, false, 'hash'], true))
                                ->thenInvalid('iq2i_vigie.record.user_identifier must be true, false, or "hash", got %s.')
                            ->end()
                        ->end()
                        ->booleanNode('uri')->defaultTrue()->end()
                        ->booleanNode('query_string')->defaultFalse()
                            ->info('Whether the query string is kept as part of "uri" — it routinely carries tokens (password resets, "_switch_user", OAuth codes) that have no business sitting in a long-lived record.')
                        ->end()
                        ->booleanNode('route')->defaultTrue()->end()
                        ->booleanNode('method')->defaultTrue()->end()
                        ->booleanNode('status_code')->defaultTrue()->end()
                        ->booleanNode('context')->defaultTrue()->end()
                        ->booleanNode('firewall')->defaultTrue()->end()
                        ->booleanNode('session_id')->defaultTrue()
                            ->info('Whether the session id is recorded. Always HMACed when enabled (record.hash_secret), never stored raw.')
                        ->end()
                        ->booleanNode('request_id')->defaultTrue()->end()
                        ->booleanNode('route_params')->defaultFalse()
                            ->info('Whether scalar route parameters (e.g. "id") are copied into context under their own name, never overwriting an existing key. Off by default.')
                        ->end()
                        ->scalarNode('hash_secret')
                            ->defaultNull()
                            ->info('Secret keying the HMAC used by user_identifier: hash and session_id. Defaults to "%kernel.secret%". Rotating it invalidates every previously stored hash.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('http')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->arrayNode('ignored_paths')
                            ->info('Regular expressions (without delimiters) matched against the request path; a match is never recorded — an exception carved out of recorded_paths (e.g. ["^/admin/_autocomplete"]). A #[Track]/#[Untrack] attribute or a tagged ActivityDeciderInterface takes precedence over it.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                            ->validate()->always(self::validatePatterns('http.ignored_paths'))->end()
                        ->end()
                        ->arrayNode('recorded_paths')
                            ->info('Regular expressions (without delimiters) matched against the request path. Nothing is recorded by default (opt-in); a path is recorded only once it matches one of these patterns (e.g. ["^/admin"] to record the backoffice) — ignored_paths still applies on top of it. Use #[Track] to opt in a controller instead of a path pattern.')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                            ->validate()->always(self::validatePatterns('http.recorded_paths'))->end()
                        ->end()
                        ->scalarNode('request_id_header')
                            ->defaultNull()
                            ->info('Name of an inbound header (e.g. "X-Request-Id") trusted as the request id when it looks like one, instead of always generating a fresh one. Null never trusts the client.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('security')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->booleanNode('enabled')->defaultTrue()->end()
                        ->booleanNode('record_non_interactive')->defaultTrue()
                            ->info('Whether a login_success from a non-interactive authenticator (RememberMeAuthenticator, a stateless API authenticator) is recorded. Set to false on a stateless API firewall to avoid one row per request.')
                        ->end()
                        ->booleanNode('record_access_denied')->defaultTrue()
                            ->info('Whether an AccessDeniedException/AccessDeniedHttpException hitting an already-authenticated token is recorded as access_denied. An anonymous visitor redirected to the login page is never a signal and is always excluded, regardless of this option.')
                        ->end()
                        ->booleanNode('record_csrf_failure')->defaultTrue()
                            ->info('Whether a false isTokenValid() on security.csrf.token_manager is recorded as csrf_failure. Requires symfony/security-csrf and framework.csrf_protection to be active; a no-op otherwise, independent of the "enabled" option above.')
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('threat')
                    ->addDefaultsIfNotSet()
                    ->info('Ingests the decisions a SIEM (CrowdSec today) hands back about suspicious IPs, ranges, sessions, users, countries and AS numbers, and exposes them through ThreatCheckerInterface. Polled by vigie:threat:sync — Vigie never blocks anything itself, the application decides (see doc/threat.md).')
                    ->children()
                        ->booleanNode('enabled')->defaultFalse()->end()
                        ->scalarNode('provider')
                            ->defaultNull()
                            ->info('Service id implementing ThreatProviderInterface, or "crowdsec" to use the built-in CrowdSec LAPI provider. Required when threat.enabled is true.')
                            ->validate()->always(self::validateServiceIdOrNull('threat.provider'))->end()
                        ->end()
                        ->scalarNode('storage')
                            ->defaultNull()
                            ->info('Service id implementing ThreatDecisionStoreInterface, "cache", or "in_memory". Defaults to "cache".')
                            ->validate()->always(self::validateServiceIdOrNull('threat.storage'))->end()
                        ->end()
                        ->arrayNode('cache')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->scalarNode('pool')
                                    ->defaultValue('cache.app')
                                    ->cannotBeEmpty()
                                    ->info('Service id of a PSR-6 CacheItemPoolInterface, holding the decisions when threat.storage is "cache" and the accepted ingest signatures when threat.ingest is on — "cache.app", a Redis pool, or "cache.adapter.filesystem" for a durable file-backed one.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('match')
                            ->addDefaultsIfNotSet()
                            ->children()
                                ->booleanNode('normalize_subject')->defaultTrue()
                                    ->info('Whether a session id and a user identifier are pushed through QueryNormalizer before being looked up, so a decision authored from the pseudonymized value a SIEM actually sees still matches. Never applies to the IP, which is always matched raw — see doc/threat.md.')
                                ->end()
                                ->integerNode('max_ranges')->defaultValue(5000)->min(1)
                                    ->info('Cap on how many "Range" decisions one IP lookup loads and tests.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('enforce')
                            ->addDefaultsIfNotSet()
                            ->info('Opt-in enforcement: turns the highest decision matching a request into a response, on kernel.request just under the firewall. Off by default — Vigie decides nothing unless asked to (see doc/threat.md).')
                            ->children()
                                ->booleanNode('enabled')->defaultFalse()->end()
                                ->arrayNode('remediations')
                                    ->info('Remediation type ("ban", "captcha", any type a scenario invents) mapped to either an HTTP status code (400-599, an empty response) or the name of a route to redirect to (302). A type absent from this map is never acted on, but ThreatDecisionMatched is still dispatched. A route named here is itself excluded from enforcement, so a captcha redirect never loops.')
                                    ->variablePrototype()->end()
                                    ->defaultValue([])
                                    ->validate()->always(self::validateRemediations())->end()
                                ->end()
                                ->arrayNode('exclude_paths')
                                    ->info('Regular expressions (without delimiters) matched against the request path; a match is never enforced — health checks, payment webhooks, a captcha page that isn\'t a named route above.')
                                    ->scalarPrototype()->end()
                                    ->defaultValue([])
                                    ->validate()->always(self::validatePatterns('threat.enforce.exclude_paths'))->end()
                                ->end()
                                ->scalarNode('country_header')
                                    ->defaultNull()
                                    ->info('Inbound header trusted to carry the client\'s country (e.g. "Cf-IPCountry" behind Cloudflare), passed to ThreatSubject::fromRequest(). Vigie ships no GeoIP database.')
                                ->end()
                                ->scalarNode('asn_header')
                                    ->defaultNull()
                                    ->info('Inbound header trusted to carry the client\'s AS number, passed to ThreatSubject::fromRequest().')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('ingest')
                            ->addDefaultsIfNotSet()
                            ->info('HTTP endpoint a SIEM pushes decisions to, the reverse of polling one with vigie:threat:sync. Nothing is reachable until the application imports "@IQ2iVigieBundle/config/routes.php" — see doc/threat.md.')
                            ->children()
                                ->booleanNode('enabled')->defaultFalse()->end()
                                ->arrayNode('providers')
                                    ->info('One shared secret per emitting SIEM, keyed by the provider name that appears in the URL and on every decision it pushes (ThreatDecision::$provider). Use an env placeholder: "%env(VIGIE_INGEST_WAZUH_SECRET)%". Required when threat.ingest.enabled is true.')
                                    ->normalizeKeys(false)
                                    ->scalarPrototype()->end()
                                    ->defaultValue([])
                                    ->validate()->always(self::validateIngestProviders())->end()
                                ->end()
                                ->integerNode('max_body_size')->defaultValue(1048576)->min(1)
                                    ->info('Largest accepted request body, in bytes — anything above is refused with a 413 before the payload is parsed. The web server\'s own limit (nginx client_max_body_size) is what actually caps memory.')
                                ->end()
                                ->integerNode('clock_skew')->defaultValue(300)->min(1)
                                    ->info('Tolerance, in seconds, on X-Vigie-Timestamp — and how long an accepted signature is remembered in threat.cache.pool to refuse a replay.')
                                ->end()
                            ->end()
                        ->end()
                        ->arrayNode('crowdsec')
                            ->addDefaultsIfNotSet()
                            ->info('Settings for the built-in CrowdSec provider (threat.provider: "crowdsec"). Targets the Local API (LAPI), never the Central API.')
                            ->children()
                                ->scalarNode('url')->defaultValue('http://127.0.0.1:8080')->cannotBeEmpty()->end()
                                ->scalarNode('api_key')
                                    ->defaultNull()
                                    ->info('Bouncer API key, created with "cscli bouncers add <name>". Use an env placeholder: "%env(CROWDSEC_API_KEY)%". Required when threat.provider is "crowdsec".')
                                ->end()
                                ->arrayNode('scopes')
                                    ->scalarPrototype()->end()
                                    ->defaultValue(['Ip', 'Range'])
                                    ->requiresAtLeastOneElement()
                                    ->info('Scopes requested from the LAPI stream, sent verbatim — the LAPI itself defaults to "ip,range" only.')
                                ->end()
                                ->arrayNode('origins')
                                    ->scalarPrototype()->end()
                                    ->defaultValue([])
                                    ->info('Restrict the stream to these decision origins ("crowdsec", "cscli", "console", "lists:<name>", "CAPI"). Empty means every origin.')
                                ->end()
                                ->arrayNode('scenarios_containing')
                                    ->scalarPrototype()->end()
                                    ->defaultValue([])
                                    ->info('Restrict the stream to decisions whose scenario contains one of these substrings.')
                                ->end()
                                ->floatNode('timeout')->defaultValue(5.0)->min(0.05)
                                    ->info('Per-request timeout, in seconds.')
                                ->end()
                                ->scalarNode('http_client')
                                    ->defaultNull()
                                    ->info('Service id of an HttpClientInterface to use instead of the default scoped one Vigie creates from "url"/"timeout" — it must carry the LAPI base URI itself, "url" is then ignored.')
                                ->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
            ->end();
    }

    /**
     * scalarNode() happily accepts a bool or an int — without this, `storage: false` would surface much
     * later as an opaque TypeError instead of a config error naming the option.
     *
     * @return \Closure(mixed): mixed
     */
    private static function validateServiceIdOrNull(string $optionName): \Closure
    {
        return static function (mixed $value) use ($optionName): mixed {
            if (null !== $value && !\is_string($value)) {
                throw new \InvalidArgumentException(\sprintf('iq2i_vigie.%s must be a service id string ("cache", "in_memory", "crowdsec", or your own service) or null, got %s.', $optionName, get_debug_type($value)));
            }

            return $value;
        };
    }

    /**
     * @return \Closure(mixed): mixed
     */
    private static function validatePatterns(string $optionName): \Closure
    {
        return static function (mixed $patterns) use ($optionName): array {
            /** @var array<mixed> $patterns */
            foreach ($patterns as $pattern) {
                if (!\is_string($pattern)) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.%s: expected a string, got %s.', $optionName, get_debug_type($pattern)));
                }

                if (false === @preg_match('{'.$pattern.'}u', '')) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.%s: "%s" is not a valid regular expression.', $optionName, $pattern));
                }
            }

            /* @var list<string> $patterns */
            return $patterns;
        };
    }

    /**
     * @return \Closure(mixed): mixed
     */
    private static function validateRemediations(): \Closure
    {
        return static function (mixed $remediations): array {
            /** @var array<mixed, mixed> $remediations */
            $validated = [];

            foreach ($remediations as $type => $action) {
                if (!\is_string($type) || '' === trim($type)) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.threat.enforce.remediations: expected a remediation type ("ban", "captcha", …) as key, got "%s".', $type));
                }

                if (\is_int($action)) {
                    if ($action < 400 || $action > 599) {
                        throw new \InvalidArgumentException(\sprintf('iq2i_vigie.threat.enforce.remediations.%s: %d is not an HTTP error status code (400-599).', $type, $action));
                    }
                } elseif (!\is_string($action) || '' === trim($action)) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.threat.enforce.remediations.%s: expected an HTTP status code between 400 and 599, or a route name, got %s.', $type, get_debug_type($action)));
                }

                // ThreatDecision lowercases and trims its own type: the table
                // has to be keyed the same way or "Ban: 403" would never match.
                $validated[strtolower(trim($type))] = \is_string($action) ? trim($action) : $action;
            }

            /* @var array<string, int|string> $validated */
            return $validated;
        };
    }

    /**
     * A provider name lands in a URL path and a PSR-6 cache key — constrained here once rather than escaped at each site.
     *
     * @return \Closure(mixed): mixed
     */
    private static function validateIngestProviders(): \Closure
    {
        return static function (mixed $providers): array {
            /** @var array<mixed, mixed> $providers */
            foreach ($providers as $name => $secret) {
                if (1 !== preg_match('/^[A-Za-z0-9_-]{1,64}$/', (string) $name)) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.threat.ingest.providers: "%s" is not a usable provider name, expected 1 to 64 characters among [A-Za-z0-9_-].', $name));
                }

                if (!\is_string($secret) || '' === $secret) {
                    throw new \InvalidArgumentException(\sprintf('iq2i_vigie.threat.ingest.providers."%s": expected a non-empty secret string, got %s.', $name, get_debug_type($secret)));
                }
            }

            /* @var array<string, string> $providers */
            return $providers;
        };
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        if (!$config['enabled']) {
            return;
        }

        $container->import(__DIR__.'/../config/services.php');

        /** @var ?string $rawStorage */
        $rawStorage = $config['storage'];
        $storage = $rawStorage ?? 'monolog';

        if ('in_memory' === $storage) {
            $container->services()
                ->set('iq2i_vigie.in_memory_storage', InMemoryActivityStorage::class)
                ->alias(InMemoryActivityStorage::class, 'iq2i_vigie.in_memory_storage');
        }

        if ('monolog' === $storage) {
            /** @var array{path: string, handlers: list<string>} $outputConfig */
            $outputConfig = $config['output'];

            if ([] === $outputConfig['handlers']) {
                $container->services()
                    ->set('iq2i_vigie.default_handler', StreamHandler::class)
                    ->arg('$stream', $outputConfig['path'])
                    ->call('setFormatter', [service('iq2i_vigie.formatter.ecs')]);

                $handlers = [new Reference('iq2i_vigie.default_handler')];
            } else {
                $handlers = array_map(static fn (string $id): Reference => new Reference($id), $outputConfig['handlers']);
            }

            $container->services()
                // Its own channel, not declared to monolog-bundle: a handler with no "channels" restriction
                // attaches to every channel, and ECS lines would end up in prod.log through the wrong formatter.
                ->set('iq2i_vigie.activity_logger', Logger::class)
                ->args(['vigie.activity', $handlers]);

            $container->services()
                ->set('iq2i_vigie.monolog_storage', MonologActivityStorage::class)
                ->arg('$logger', service('iq2i_vigie.activity_logger'))
                ->arg('$clock', service(ClockInterface::class))
                ->arg('$app', $config['app'])
                ->arg('$env', $config['env'])
                ->alias(MonologActivityStorage::class, 'iq2i_vigie.monolog_storage');
        }

        $resolvedStorage = match ($storage) {
            'in_memory' => 'iq2i_vigie.in_memory_storage',
            'monolog' => 'iq2i_vigie.monolog_storage',
            default => $storage,
        };

        $builder->setAlias(ActivityStorageInterface::class, $resolvedStorage);

        /** @var array{ip_address: bool|string, user_agent: bool, user_identifier: bool|string, uri: bool, query_string: bool, route: bool, method: bool, status_code: bool, context: bool, firewall: bool, session_id: bool, request_id: bool, route_params: bool, hash_secret: ?string} $recordConfig */
        $recordConfig = $config['record'];

        $builder->getDefinition(RecordingOptions::class)
            ->setArguments([
                '$ipAddress' => $recordConfig['ip_address'],
                '$userIdentifier' => $recordConfig['user_identifier'],
                '$userAgent' => $recordConfig['user_agent'],
                '$uri' => $recordConfig['uri'],
                '$route' => $recordConfig['route'],
                '$method' => $recordConfig['method'],
                '$statusCode' => $recordConfig['status_code'],
                '$context' => $recordConfig['context'],
                '$firewall' => $recordConfig['firewall'],
                '$sessionId' => $recordConfig['session_id'],
                '$requestId' => $recordConfig['request_id'],
            ]);

        if (\is_string($recordConfig['hash_secret'])) {
            $builder->getDefinition(Pseudonymizer::class)
                ->setArgument('$secret', $recordConfig['hash_secret']);
        }

        /** @var array{enabled: bool, ignored_paths: list<string>, recorded_paths: list<string>, request_id_header: ?string} $httpConfig */
        $httpConfig = $config['http'];

        if ($httpConfig['enabled']) {
            $builder->getDefinition(TrackingDecider::class)
                ->setArgument('$ignoredPaths', $httpConfig['ignored_paths'])
                ->setArgument('$recordedPaths', $httpConfig['recorded_paths']);

            $builder->getDefinition(HttpActivitySubscriber::class)
                ->setArgument('$queryString', $recordConfig['query_string'])
                ->setArgument('$routeParams', $recordConfig['route_params']);

            if ($builder->hasDefinition(RequestIdSubscriber::class)) {
                $builder->getDefinition(RequestIdSubscriber::class)
                    ->setArgument('$requestIdHeader', $httpConfig['request_id_header']);
            }
        } else {
            $builder->removeDefinition(HttpActivitySubscriber::class);
            $builder->removeDefinition(TrackingDecider::class);

            if ($builder->hasDefinition(TrackingAttributeSubscriber::class)) {
                $builder->removeDefinition(TrackingAttributeSubscriber::class);
            }

            if ($builder->hasDefinition(RequestIdSubscriber::class)) {
                $builder->removeDefinition(RequestIdSubscriber::class);
            }
        }

        /** @var array{enabled: bool, record_non_interactive: bool, record_access_denied: bool, record_csrf_failure: bool} $securityConfig */
        $securityConfig = $config['security'];

        if ($builder->hasDefinition(SecurityActivitySubscriber::class)) {
            if ($securityConfig['enabled']) {
                $builder->getDefinition(SecurityActivitySubscriber::class)
                    ->setArgument('$recordNonInteractive', $securityConfig['record_non_interactive'])
                    ->setArgument('$recordAccessDenied', $securityConfig['record_access_denied']);
            } else {
                $builder->removeDefinition(SecurityActivitySubscriber::class);
            }
        }

        // Independent of security.enabled above: it decorates security.csrf.token_manager directly, nothing
        // to do with SecurityActivitySubscriber. Removing the definition here, before DecoratorServicePass runs, turns the option off.
        if ($builder->hasDefinition(RecordingCsrfTokenManager::class) && !$securityConfig['record_csrf_failure']) {
            $builder->removeDefinition(RecordingCsrfTokenManager::class);
        }

        /** @var array{enabled: bool, provider: ?string, storage: ?string, cache: array{pool: string}, match: array{normalize_subject: bool, max_ranges: int}, enforce: array{enabled: bool, remediations: array<string, int|string>, exclude_paths: list<string>, country_header: ?string, asn_header: ?string}, ingest: array{enabled: bool, providers: array<string, string>, max_body_size: int, clock_skew: int}, crowdsec: array{url: string, api_key: ?string, scopes: list<string>, origins: list<string>, scenarios_containing: list<string>, timeout: float, http_client: ?string}} $threatConfig */
        $threatConfig = $config['threat'];

        if (!$threatConfig['enabled'] && $threatConfig['enforce']['enabled']) {
            throw new \LogicException('iq2i_vigie.threat.enforce.enabled is true but iq2i_vigie.threat.enabled is false — enforcement acts on the decisions the threat subsystem stores, set "iq2i_vigie.threat.enabled: true" as well (see doc/threat.md).');
        }

        if (!$threatConfig['enabled'] && $threatConfig['ingest']['enabled']) {
            throw new \LogicException('iq2i_vigie.threat.ingest.enabled is true but iq2i_vigie.threat.enabled is false — the ingest endpoint writes into the threat store, which only exists once the subsystem is on (see doc/threat.md).');
        }

        if ($threatConfig['enabled']) {
            $this->loadThreatExtension($threatConfig, $container, $builder);
        }

        if ($builder->getParameter('kernel.debug') && class_exists(WebProfilerBundle::class)) {
            $container->import(__DIR__.'/../config/services_profiler.php');

            $builder->getDefinition(VigieDataCollector::class)
                ->setArgument('$httpEnabled', $httpConfig['enabled'])
                ->setArgument('$recordedPaths', $httpConfig['recorded_paths'])
                ->setArgument('$ignoredPaths', $httpConfig['ignored_paths']);
        }
    }

    /**
     * @param array{provider: ?string, storage: ?string, cache: array{pool: string}, match: array{normalize_subject: bool, max_ranges: int}, enforce: array{enabled: bool, remediations: array<string, int|string>, exclude_paths: list<string>, country_header: ?string, asn_header: ?string}, ingest: array{enabled: bool, providers: array<string, string>, max_body_size: int, clock_skew: int}, crowdsec: array{url: string, api_key: ?string, scopes: list<string>, origins: list<string>, scenarios_containing: list<string>, timeout: float, http_client: ?string}} $threatConfig
     */
    private function loadThreatExtension(array $threatConfig, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->import(__DIR__.'/../config/services_threat.php');

        $storage = $threatConfig['storage'] ?? 'cache';

        $storageId = match ($storage) {
            'cache' => CacheThreatDecisionStore::class,
            'in_memory' => 'iq2i_vigie.threat.in_memory_store',
            default => $storage,
        };

        if ('cache' === $storage) {
            $container->services()
                ->set(CacheThreatDecisionStore::class)
                ->arg('$pool', new Reference($threatConfig['cache']['pool']));
        }

        if ('in_memory' === $storage) {
            $container->services()
                ->set('iq2i_vigie.threat.in_memory_store', InMemoryThreatDecisionStore::class)
                ->alias(InMemoryThreatDecisionStore::class, 'iq2i_vigie.threat.in_memory_store');
        }

        $builder->setAlias(ThreatDecisionStoreInterface::class, $storageId);

        $matchConfig = $threatConfig['match'];

        $builder->getDefinition(ThreatChecker::class)
            ->setArgument('$normalizeSubject', $matchConfig['normalize_subject'])
            ->setArgument('$maxRanges', $matchConfig['max_ranges']);

        $enforceConfig = $threatConfig['enforce'];

        if ($enforceConfig['enabled']) {
            if ([] !== array_filter($enforceConfig['remediations'], \is_string(...)) && !interface_exists(UrlGeneratorInterface::class)) {
                throw new \LogicException('iq2i_vigie.threat.enforce.remediations maps a remediation to a route name but symfony/routing is not installed. Try running "composer require symfony/routing".');
            }

            $builder->getDefinition(ThreatEnforcementSubscriber::class)
                ->setArgument('$remediations', $enforceConfig['remediations'])
                ->setArgument('$excludePaths', $enforceConfig['exclude_paths'])
                ->setArgument('$countryHeader', $enforceConfig['country_header'])
                ->setArgument('$asnHeader', $enforceConfig['asn_header']);
        } else {
            $builder->removeDefinition(ThreatEnforcementSubscriber::class);
        }

        $ingestConfig = $threatConfig['ingest'];

        if ($ingestConfig['enabled']) {
            if ([] === $ingestConfig['providers']) {
                throw new \LogicException('iq2i_vigie.threat.ingest.enabled is true but "iq2i_vigie.threat.ingest.providers" is empty — declare one shared secret per emitting SIEM (see doc/threat.md).');
            }

            if (!interface_exists(UrlGeneratorInterface::class)) {
                throw new \LogicException('iq2i_vigie.threat.ingest.enabled is true but symfony/routing is not installed. Try running "composer require symfony/routing".');
            }

            $container->import(__DIR__.'/../config/services_threat_ingest.php');

            $builder->getDefinition(IngestController::class)
                ->setArgument('$replayPool', new Reference($threatConfig['cache']['pool']))
                ->setArgument('$secrets', $ingestConfig['providers'])
                ->setArgument('$maxBodySize', $ingestConfig['max_body_size'])
                ->setArgument('$clockSkew', $ingestConfig['clock_skew']);
        }

        // No provider: the store, the checker, vigie:threat:list and the ingest endpoint above still work
        // (decisions can be seeded or pushed) — vigie:threat:sync simply has nothing to pull.
        if (null === $threatConfig['provider']) {
            return;
        }

        if ('crowdsec' === $threatConfig['provider']) {
            if (!interface_exists(HttpClientInterface::class)) {
                throw new \LogicException('iq2i_vigie.threat.provider is set to "crowdsec" but symfony/http-client is not installed. Try running "composer require symfony/http-client".');
            }

            $crowdsecConfig = $threatConfig['crowdsec'];

            if (null === $crowdsecConfig['api_key']) {
                throw new \LogicException('iq2i_vigie.threat.provider is set to "crowdsec" but "iq2i_vigie.threat.crowdsec.api_key" is not set — create one with "cscli bouncers add <name>" (see doc/threat.md).');
            }

            $container->import(__DIR__.'/../config/services_threat_crowdsec.php');

            if (null !== $crowdsecConfig['http_client']) {
                $builder->getDefinition(CrowdSecProvider::class)
                    ->setArgument('$client', new Reference($crowdsecConfig['http_client']));
            } else {
                $builder->getDefinition('iq2i_vigie.threat.crowdsec.http_client')
                    ->setArguments([$crowdsecConfig['url'], ['timeout' => $crowdsecConfig['timeout']]]);
            }

            $builder->getDefinition(CrowdSecProvider::class)
                ->setArgument('$apiKey', $crowdsecConfig['api_key'])
                ->setArgument('$scopes', $crowdsecConfig['scopes'])
                ->setArgument('$origins', $crowdsecConfig['origins'])
                ->setArgument('$scenariosContaining', $crowdsecConfig['scenarios_containing']);

            $providerId = CrowdSecProvider::class;
        } else {
            $providerId = $threatConfig['provider'];
        }

        $builder->setAlias(ThreatProviderInterface::class, $providerId);

        $builder->getDefinition(ThreatSynchronizer::class)
            ->setArgument('$provider', new Reference($providerId));
    }
}
