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

namespace IQ2i\VigieBundle\Tests\Threat\Ingest;

use IQ2i\VigieBundle\Threat\Ingest\RequestSigner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RequestSignerTest extends TestCase
{
    public function testAFreshlySignedPayloadVerifies(): void
    {
        $signature = RequestSigner::sign('secret', '1700000000', '{"added":[]}');

        self::assertTrue(RequestSigner::verify('secret', '1700000000', '{"added":[]}', $signature));
    }

    public function testTheSignatureCarriesTheAlgorithmPrefix(): void
    {
        self::assertStringStartsWith('sha256=', RequestSigner::sign('secret', '1700000000', '{}'));
    }

    /**
     * @return iterable<string, array{string, string, string, string}>
     */
    public static function tamperedInputs(): iterable
    {
        $secret = 'secret';
        $timestamp = '1700000000';
        $body = '{"added":[]}';
        $signature = RequestSigner::sign($secret, $timestamp, $body);

        yield 'wrong secret' => ['wrong-secret', $timestamp, $body, $signature];
        yield 'tampered body' => [$secret, $timestamp, '{"added":[{}]}', $signature];
        yield 'tampered timestamp' => [$secret, '1700000001', $body, $signature];
        yield 'truncated signature' => [$secret, $timestamp, $body, substr($signature, 0, -4)];
        yield 'missing algorithm prefix' => [$secret, $timestamp, $body, substr($signature, 7)];
    }

    #[DataProvider('tamperedInputs')]
    public function testATamperedInputDoesNotVerify(string $secret, string $timestamp, string $body, string $signature): void
    {
        self::assertFalse(RequestSigner::verify($secret, $timestamp, $body, $signature));
    }
}
