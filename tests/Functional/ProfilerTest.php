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

use IQ2i\VigieBundle\DataCollector\VigieDataCollector;
use IQ2i\VigieBundle\Http\TrackingSource;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;

final class ProfilerTest extends FunctionalTestCase
{
    public function testTrackedControllerIsRecordedWithAttributeSource(): void
    {
        $client = self::createClient(['environment' => 'profiler']);

        $client->request('GET', '/ping');

        $collector = self::collector($client);
        self::assertTrue($collector->getDecision()['recorded']);
        self::assertSame(TrackingSource::Attribute->name, $collector->getDecision()['source']);
        self::assertSame(1, $collector->getCount());
        self::assertSame('http_request', $collector->getActivities()[0]['type']);
    }

    public function testPlainControllerIsNotRecordedWithDefaultSource(): void
    {
        $client = self::createClient(['environment' => 'profiler']);

        $client->request('GET', '/plain');

        $collector = self::collector($client);
        self::assertFalse($collector->getDecision()['recorded']);
        self::assertSame(TrackingSource::Default->name, $collector->getDecision()['source']);
        self::assertSame(0, $collector->getCount());
    }

    public function testUntrackedControllerIsNotRecordedWithAttributeSource(): void
    {
        $client = self::createClient(['environment' => 'profiler']);

        $client->request('GET', '/untracked');

        $collector = self::collector($client);
        self::assertFalse($collector->getDecision()['recorded']);
        self::assertSame(TrackingSource::Attribute->name, $collector->getDecision()['source']);
    }

    public function testThePanelRendersWithTheVigieToken(): void
    {
        $client = self::createClient(['environment' => 'profiler']);

        $client->request('GET', '/ping');

        $token = $client->getResponse()->headers->get('X-Debug-Token');
        self::assertNotNull($token);

        $client->request('GET', '/_profiler/'.$token.'?panel=vigie');

        self::assertTrue($client->getResponse()->isSuccessful());
        self::assertStringContainsString('Vigie', (string) $client->getResponse()->getContent());
        self::assertStringContainsString('Recorded', (string) $client->getResponse()->getContent());
    }

    private static function collector(KernelBrowser $client): VigieDataCollector
    {
        $profile = $client->getProfile();

        if (!$profile) {
            self::fail('No profile was collected for this request.');
        }

        $collector = $profile->getCollector('vigie');
        self::assertInstanceOf(VigieDataCollector::class, $collector);

        return $collector;
    }
}
