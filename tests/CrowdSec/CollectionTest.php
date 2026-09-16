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

namespace IQ2i\VigieBundle\Tests\CrowdSec;

use IQ2i\VigieBundle\Model\ActivityType;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * Guards crowdsec/ against drifting from doc/schema/activity.json the way EcsSchemaTest guards the
 * ECS mapping itself: a schema change that silently breaks the parser or a scenario fails here
 * instead of failing quietly on a production CrowdSec host.
 */
final class CollectionTest extends TestCase
{
    private const CROWDSEC_DIR = __DIR__.'/../../crowdsec';

    // The two scopes ThreatChecker::USER_SCOPE/SESSION_SCOPE know about, beyond the four canonical
    // ones ThreatScope::of() folds (Ip, Range, Country, AS). A scenario's scope.type must be one of
    // these or a canonical one; a profile filter (Alert.GetScope() == "...") must reference one of
    // these to ever route a non-Ip decision.
    private const NON_CANONICAL_SCOPES = ['username', 'session'];

    /**
     * @return array<string, mixed>
     */
    private function schemaProperties(): array
    {
        $json = file_get_contents(\dirname(__DIR__, 2).'/doc/schema/activity.json');
        \assert(false !== $json);

        /** @var array{properties: array<string, mixed>} $schema */
        $schema = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);

        return $schema['properties'];
    }

    /**
     * @return list<string> every JsonExtract(evt.Line.Raw, "...") / '...' path in a file
     */
    private static function jsonExtractPaths(string $path): array
    {
        $content = file_get_contents($path);
        \assert(false !== $content);

        preg_match_all('/JsonExtract\(evt\.Line\.Raw,\s*[\'"]([^\'"]+)[\'"]\)/', $content, $matches);

        return $matches[1];
    }

    public function testTheParserYamlIsWellFormed(): void
    {
        $parsed = Yaml::parseFile(self::CROWDSEC_DIR.'/parsers/s01-parse/vigie-ecs.yaml');

        self::assertIsArray($parsed);
        self::assertSame('local/vigie-ecs', $parsed['name'] ?? null);
    }

    public function testEveryJsonExtractPathInTheParserExistsInTheSchema(): void
    {
        $properties = $this->schemaProperties();
        $paths = self::jsonExtractPaths(self::CROWDSEC_DIR.'/parsers/s01-parse/vigie-ecs.yaml');

        self::assertNotEmpty($paths, 'The parser should extract at least one field.');

        foreach ($paths as $path) {
            $segments = explode('.', $path);
            $node = $properties;

            foreach ($segments as $i => $segment) {
                self::assertArrayHasKey($segment, $node, \sprintf(
                    '"%s" (from JsonExtract path "%s") has no counterpart in doc/schema/activity.json.',
                    $segment,
                    $path,
                ));

                if ($i === array_key_last($segments)) {
                    break;
                }

                /** @var array{properties?: array<string, mixed>} $child */
                $child = $node[$segment];
                $grandchildProperties = $child['properties'] ?? null;

                self::assertIsArray($grandchildProperties, \sprintf(
                    '"%s" is a leaf in the schema, but JsonExtract path "%s" descends further into it.',
                    $segment,
                    $path,
                ));

                $node = $grandchildProperties;
            }
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function scenarioFiles(): iterable
    {
        $files = glob(self::CROWDSEC_DIR.'/scenarios/*.yaml');
        self::assertNotEmpty($files);

        foreach ($files as $file) {
            yield basename($file) => [$file];
        }
    }

    #[DataProvider('scenarioFiles')]
    public function testTheScenarioYamlIsWellFormed(string $file): void
    {
        $parsed = Yaml::parseFile($file);

        self::assertIsArray($parsed);
        self::assertSame('leaky', $parsed['type'] ?? null);

        $name = $parsed['name'] ?? null;
        self::assertIsString($name);
        self::assertStringStartsWith('local/vigie-', $name);

        $filter = $parsed['filter'] ?? null;
        self::assertIsString($filter);
        self::assertStringContainsString(
            "evt.Meta.remediation == ''",
            $filter,
            'A scenario must exclude lines Vigie itself already enforced (vigie.remediation), or a ban keeps re-triggering the scenario that issued it.',
        );

        /** @var array{remediation?: bool, service?: string} $labels */
        $labels = $parsed['labels'] ?? [];
        self::assertTrue(
            $labels['remediation'] ?? false,
            \sprintf('%s must set labels.remediation: true, or a LAPI profile filtering on Alert.Remediation == true never matches it.', $name),
        );
        self::assertNotEmpty($labels['service'] ?? null);

        /** @var array{type?: string, expression?: string}|null $scope */
        $scope = $parsed['scope'] ?? null;

        if (null !== $scope) {
            self::assertContains(
                $scope['type'] ?? null,
                self::NON_CANONICAL_SCOPES,
                \sprintf('%s declares a scope.type not among %s, so no LAPI profile in profiles/vigie.yaml can route it and ThreatChecker never looks it up under that name.', $name, implode('/', self::NON_CANONICAL_SCOPES)),
            );
            self::assertNotEmpty($scope['expression'] ?? null);
        }
    }

    #[DataProvider('scenarioFiles')]
    public function testEveryVigieTypeCitedInAScenarioIsAKnownActivityType(string $file): void
    {
        $content = file_get_contents($file);
        \assert(false !== $content);

        preg_match_all('/evt\.Meta\.vigie_type\s*==\s*[\'"]([^\'"]+)[\'"]/', $content, $matches);

        $values = array_map(static fn (\BackedEnum $case): string => $case->value, ActivityType::cases());

        // Not every scenario compares evt.Meta.vigie_type against a literal (vigie-idor-probing
        // filters on subject_owner instead); assert something regardless, or an empty match set
        // would make this test risky.
        self::assertSame(
            [],
            array_values(array_diff($matches[1], $values)),
            \sprintf('%s cites a vigie.type value with no counterpart in ActivityType.', basename($file)),
        );
    }

    public function testTheCollectionListsEveryParserAndScenario(): void
    {
        /** @var array{parsers?: list<string>, scenarios?: list<string>} $collection */
        $collection = Yaml::parseFile(self::CROWDSEC_DIR.'/collections/vigie.yaml');

        self::assertSame(['local/vigie-ecs'], $collection['parsers'] ?? null);

        $files = glob(self::CROWDSEC_DIR.'/scenarios/*.yaml');
        self::assertNotEmpty($files);

        $expected = array_map(
            static fn (string $file): string => 'local/'.basename($file, '.yaml'),
            $files,
        );
        sort($expected);

        $actual = $collection['scenarios'] ?? [];
        sort($actual);

        self::assertSame($expected, $actual);
    }

    public function testTheAcquisExampleIsWellFormed(): void
    {
        /** @var array{filenames?: list<string>, labels?: array{type?: string}} $acquis */
        $acquis = Yaml::parseFile(self::CROWDSEC_DIR.'/acquis/vigie.yaml.example');

        self::assertSame('vigie_ecs', $acquis['labels']['type'] ?? null);
    }

    public function testTheProfileYamlIsWellFormed(): void
    {
        $parsed = Yaml::parseFile(self::CROWDSEC_DIR.'/profiles/vigie.yaml');

        self::assertIsArray($parsed);
        self::assertIsString($parsed['name'] ?? null);

        /** @var list<string> $filters */
        $filters = $parsed['filters'] ?? [];
        self::assertNotEmpty($filters, 'profiles/vigie.yaml must declare at least one filter.');
    }

    /**
     * Every scope a profile filter routes on (Alert.GetScope() == "...") must be a scope at least one
     * scenario actually declares, or the profile is dead weight: it will never see a matching alert.
     */
    public function testEveryProfileScopeMatchesAScenarioScope(): void
    {
        $profileContent = file_get_contents(self::CROWDSEC_DIR.'/profiles/vigie.yaml');
        \assert(false !== $profileContent);

        preg_match_all('/Alert\.GetScope\(\)\s*==\s*[\'"]([^\'"]+)[\'"]/', $profileContent, $profileMatches);
        $profileScopes = array_unique($profileMatches[1]);

        self::assertNotEmpty($profileScopes, 'profiles/vigie.yaml should route on at least one Alert.GetScope() filter.');

        $files = glob(self::CROWDSEC_DIR.'/scenarios/*.yaml');
        self::assertNotEmpty($files);

        $scenarioScopes = [];

        foreach ($files as $file) {
            /** @var array{scope?: array{type?: string}} $parsed */
            $parsed = Yaml::parseFile($file);
            $type = $parsed['scope']['type'] ?? null;

            if (null !== $type) {
                $scenarioScopes[] = $type;
            }
        }

        foreach ($profileScopes as $profileScope) {
            if ('Ip' === $profileScope) {
                continue; // The LAPI's own default scope, never declared explicitly by a scenario's scope directive.
            }

            self::assertContains(
                $profileScope,
                $scenarioScopes,
                \sprintf('profiles/vigie.yaml routes on scope "%s", but no scenario in crowdsec/scenarios declares a scope.type of "%s".', $profileScope, $profileScope),
            );
        }
    }
}
