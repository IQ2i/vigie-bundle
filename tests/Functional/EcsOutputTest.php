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

namespace IQ2i\VigieBundle\Tests\Functional;

use IQ2i\VigieBundle\Monolog\EcsDocument;
use Monolog\Handler\TestHandler;

final class EcsOutputTest extends FunctionalTestCase
{
    protected function setUp(): void
    {
        @unlink($this->logPath('ecs_output'));
        @unlink($this->logPath('ecs_output_custom_handler'));
    }

    public function testATrackedRequestIsWrittenAsAnEcsLine(): void
    {
        $client = self::createClient(['environment' => 'ecs_output']);
        $client->disableReboot();

        $client->request('GET', '/ping');

        $path = $this->logPath('ecs_output');
        self::assertFileExists($path);

        $line = file_get_contents($path);
        self::assertNotFalse($line);
        self::assertStringEndsWith("\n", $line);
        self::assertSame(1, substr_count($line, "\n"));

        /** @var array<string, mixed> $data */
        $data = json_decode($line, true, flags: \JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('@timestamp', $data);
        self::assertArrayHasKey('message', $data);
        self::assertSame(EcsDocument::ECS_VERSION, self::node($data['ecs'] ?? null)['version'] ?? null);
        self::assertSame('event', self::node($data['event'] ?? null)['kind'] ?? null);
        self::assertSame('http_request', self::node($data['vigie'] ?? null)['type'] ?? null);
        self::assertSame('app_ping', self::node($data['vigie'] ?? null)['route'] ?? null);
        self::assertSame('shop', self::node($data['service'] ?? null)['name'] ?? null);
        self::assertSame(200, self::node(self::node($data['http'] ?? null)['response'] ?? null)['status_code'] ?? null);
    }

    public function testAConfiguredHandlerIsUsedVerbatimWithTheEcsDocumentAsContext(): void
    {
        $client = self::createClient(['environment' => 'ecs_output_custom_handler']);
        $client->disableReboot();

        $client->request('GET', '/ping');

        self::assertFileDoesNotExist($this->logPath('ecs_output_custom_handler'));

        /** @var TestHandler $handler */
        $handler = self::getContainer()->get('app.test_handler');
        $records = $handler->getRecords();

        self::assertCount(1, $records);
        self::assertSame('vigie.activity', $records[0]->channel);

        $context = $records[0]->context;
        self::assertSame('http_request', self::node($context['vigie'] ?? null)['type'] ?? null);
    }

    private function logPath(string $environment): string
    {
        return sys_get_temp_dir().'/vigie/tests/var/'.$environment.'/log/vigie.jsonl';
    }

    /**
     * @return array<string, mixed>
     */
    private static function node(mixed $value): array
    {
        self::assertIsArray($value);

        /** @var array<string, mixed> $typed */
        $typed = $value;

        return $typed;
    }
}
