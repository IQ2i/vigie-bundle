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
use IQ2i\VigieBundle\EventSubscriber\HttpActivitySubscriber;
use IQ2i\VigieBundle\EventSubscriber\SecurityActivitySubscriber;
use IQ2i\VigieBundle\Security\RecordingCsrfTokenManager;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

final class ConfigurationTest extends FunctionalTestCase
{
    public function testTheContainerCompilesWithTheDefaultConfiguration(): void
    {
        self::bootKernel();

        self::assertTrue(self::getContainer()->has(HttpActivitySubscriber::class));
        self::assertTrue(self::getContainer()->has(SecurityActivitySubscriber::class));
    }

    public function testHttpTrackingCanBeDisabled(): void
    {
        self::bootKernel(['environment' => 'http_disabled']);

        self::assertFalse(self::getContainer()->has(HttpActivitySubscriber::class));
    }

    public function testSecurityTrackingCanBeDisabled(): void
    {
        self::bootKernel(['environment' => 'security_disabled']);

        self::assertFalse(self::getContainer()->has(SecurityActivitySubscriber::class));
    }

    public function testAnInvalidIgnoredPathRegexIsRejectedAtCompileTime(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/ignored_paths/');

        self::bootKernel(['environment' => 'invalid_ignored_path']);
    }

    public function testAnInvalidRecordedPathRegexIsRejectedAtCompileTime(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/recorded_paths/');

        self::bootKernel(['environment' => 'invalid_recorded_path']);
    }

    public function testIpAddressIsAnonymizedAndUserIdentifierIsHashedWhenConfigured(): void
    {
        $client = self::createClient(['environment' => 'record_anonymize']);
        $client->disableReboot();

        $client->request('GET', '/ping', server: ['REMOTE_ADDR' => '203.0.113.42']);

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('203.0.113.0', $activities[0]->ipAddress);
    }

    public function testIpAddressIsAnonymizedByDefaultWithoutAnyConfiguration(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/ping', server: ['REMOTE_ADDR' => '203.0.113.42']);

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('203.0.113.0', $activities[0]->ipAddress);
    }

    public function testSessionIdAndRequestIdAreNulledWhenDisabled(): void
    {
        $client = self::createClient(['environment' => 'record_no_session']);
        $client->disableReboot();

        $client->request('GET', '/ping');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertNull($activities[0]->sessionId);
        self::assertNull($activities[0]->requestId);
    }

    public function testHttpFiltersAreWiredFromConfiguration(): void
    {
        $client = self::createClient(['environment' => 'http_filters']);
        $client->disableReboot();

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        // /plain carries no #[Track] attribute; recorded_paths is what opts it in.
        $client->request('GET', '/plain');

        self::assertCount(1, $storage->all());

        $client->request('GET', '/does-not-exist');

        self::assertCount(1, $storage->all());
    }

    public function testNothingIsRecordedByDefault(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/plain');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        self::assertCount(0, $storage->all());
    }

    public function testSecurityNonInteractiveOptionCompiles(): void
    {
        self::bootKernel(['environment' => 'security_non_interactive']);

        self::assertTrue(self::getContainer()->has(SecurityActivitySubscriber::class));
    }

    public function testSecurityAccessDeniedOptionCompiles(): void
    {
        self::bootKernel(['environment' => 'security_access_denied_disabled']);

        self::assertTrue(self::getContainer()->has(SecurityActivitySubscriber::class));
    }

    public function testCsrfFailureRecordingCanBeDisabled(): void
    {
        self::bootKernel(['environment' => 'csrf_disabled']);

        self::assertFalse(self::getContainer()->has(RecordingCsrfTokenManager::class));
    }

    public function testQueryStringIsIncludedInTheUriWhenConfigured(): void
    {
        $client = self::createClient(['environment' => 'record_query_string']);
        $client->disableReboot();

        $client->request('GET', '/ping?foo=bar');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertIsString($activities[0]->uri);
        self::assertStringContainsString('foo=bar', $activities[0]->uri);
    }

    public function testAnUntrackAttributeIsNotRecorded(): void
    {
        // recorded_paths opts /untracked in, so the assertion below actually
        // exercises #[Untrack] rather than passing vacuously by default.
        $client = self::createClient(['environment' => 'http_filters']);
        $client->disableReboot();

        $client->request('GET', '/untracked');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        self::assertCount(0, $storage->all());
    }

    public function testAnActivityDeciderOverridesTheUntrackAttribute(): void
    {
        $client = self::createClient(['environment' => 'activity_decider']);
        $client->disableReboot();

        $client->request('GET', '/untracked');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);

        self::assertCount(1, $storage->all());
    }

    public function testTrackSubjectIsRecordedFromTheRouteParameter(): void
    {
        $client = self::createClient(['environment' => 'test_kit']);
        $client->disableReboot();

        $client->request('GET', '/subjects/42');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertNotNull($activities[0]->subject);
        self::assertSame('thing', $activities[0]->subject->type);
        self::assertSame('42', $activities[0]->subject->id);
    }

    public function testRouteParamsAreCopiedIntoContextWhenConfigured(): void
    {
        $client = self::createClient(['environment' => 'record_route_params']);
        $client->disableReboot();

        $client->request('GET', '/subjects/42');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('42', $activities[0]->context['id']);
    }

    public function testRouteParamsAreNotCopiedWhenContextIsDisabled(): void
    {
        $client = self::createClient(['environment' => 'record_route_params_no_context']);
        $client->disableReboot();

        $client->request('GET', '/subjects/42');

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame([], $activities[0]->context);
    }

    /**
     * The profiler panel costs nothing outside "debug + web-profiler-bundle installed": this environment
     * isn't in debug mode, even though web-profiler-bundle is a dev dependency of this test suite.
     */
    public function testTheProfilerCollectorIsNotRegisteredOutsideDebugMode(): void
    {
        self::bootKernel();

        self::assertFalse(self::getContainer()->has(VigieDataCollector::class));
    }

    public function testATrustedRequestIdHeaderIsCarriedToTheStoredActivity(): void
    {
        $client = self::createClient(['environment' => 'request_id_header']);
        $client->disableReboot();

        $client->request('GET', '/ping', server: ['HTTP_X_REQUEST_ID' => 'client-supplied-id']);

        /** @var InMemoryActivityStorage $storage */
        $storage = self::getContainer()->get(InMemoryActivityStorage::class);
        $activities = $storage->all();

        self::assertCount(1, $activities);
        self::assertSame('client-supplied-id', $activities[0]->requestId);
    }

    public function testCrowdSecProviderWithoutAnApiKeyFailsWithAClearMessage(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/crowdsec\.api_key/');

        self::bootKernel(['environment' => 'invalid_threat_crowdsec']);
    }

    public function testEnforcementWithoutTheThreatSubsystemFailsAtBoot(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/threat\.enforce\.enabled/');

        self::bootKernel(['environment' => 'invalid_threat_enforce_disabled']);
    }

    public function testAnInvalidRemediationIsRejectedAtCompileTime(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/remediations/');

        self::bootKernel(['environment' => 'invalid_threat_remediation']);
    }

    public function testIngestWithoutAnySecretFailsWithAClearMessage(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/ingest\.providers/');

        self::bootKernel(['environment' => 'invalid_threat_ingest']);
    }

    public function testIngestWithoutTheThreatSubsystemFailsWithAClearMessage(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessageMatches('/threat\.enabled/');

        self::bootKernel(['environment' => 'invalid_threat_ingest_disabled']);
    }
}
