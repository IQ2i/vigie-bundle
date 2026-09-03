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

namespace IQ2i\VigieBundle\Tests;

use IQ2i\VigieBundle\IQ2iVigieBundle;
use IQ2i\VigieBundle\Processor\TokenProcessor;
use IQ2i\VigieBundle\Recorder\ActivityRecorderInterface;
use IQ2i\VigieBundle\Security\RecordingCsrfTokenManager;
use IQ2i\VigieBundle\Storage\ActivityStorageInterface;
use IQ2i\VigieBundle\Storage\InMemoryActivityStorage;
use IQ2i\VigieBundle\Storage\MonologActivityStorage;
use Monolog\Handler\StreamHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

final class IQ2iVigieBundleTest extends TestCase
{
    public function testItIsAnAbstractBundle(): void
    {
        self::assertInstanceOf(AbstractBundle::class, new IQ2iVigieBundle());
    }

    /**
     * TokenStorageInterface is an interface: class_exists() unconditionally returns false for it, which
     * would silently skip registering TokenProcessor even with security-core installed.
     */
    public function testTokenProcessorIsRegisteredWhenSecurityCoreIsAvailable(): void
    {
        self::assertTrue(interface_exists(TokenStorageInterface::class), 'This test requires symfony/security-core to be installed.');

        $builder = $this->compiledContainer();

        self::assertTrue($builder->hasDefinition(TokenProcessor::class));
        self::assertTrue($builder->getDefinition(TokenProcessor::class)->hasTag('vigie.activity_processor'));
    }

    /**
     * DecoratorServicePass hasn't run yet here — compiledContainer() never calls compile() — so the raw decoration metadata is still readable straight off the definition.
     */
    public function testTheCsrfDecoratorHasANegativePriorityToEndUpOutermost(): void
    {
        self::assertTrue(interface_exists(CsrfTokenManagerInterface::class), 'This test requires symfony/security-csrf to be installed.');

        $builder = $this->compiledContainer();

        self::assertSame(
            ['security.csrf.token_manager', null, -10, ContainerInterface::IGNORE_ON_INVALID_REFERENCE],
            $builder->getDefinition(RecordingCsrfTokenManager::class)->getDecoratedService(),
        );
    }

    public function testEveryAliasItRegistersIsPrivate(): void
    {
        $builder = $this->compiledContainer();

        foreach ([
            ActivityStorageInterface::class,
            ActivityRecorderInterface::class,
        ] as $id) {
            self::assertFalse($builder->getAlias($id)->isPublic(), \sprintf('Alias "%s" should be private.', $id));
        }
    }

    /**
     * scalarNode() accepts a bool. Without the node's validate(), a `storage: false` would crash container
     * compilation with an opaque TypeError instead of a config error naming the option.
     */
    public function testANonStringStorageIsRejectedAsAConfigError(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->expectExceptionMessageMatches('/iq2i_vigie\.storage must be a service id string/');

        $this->compiledContainer(['storage' => false]);
    }

    public function testMonologStorageIsUsedByDefault(): void
    {
        $builder = $this->compiledContainer([]);

        self::assertSame('iq2i_vigie.monolog_storage', (string) $builder->getAlias(ActivityStorageInterface::class));
        self::assertTrue($builder->hasAlias(MonologActivityStorage::class));
    }

    public function testTheDefaultHandlerWritesToOutputPathWithTheEcsFormatter(): void
    {
        $builder = $this->compiledContainer([]);

        $handler = $builder->getDefinition('iq2i_vigie.default_handler');
        self::assertSame(StreamHandler::class, $handler->getClass());
        self::assertSame('%kernel.logs_dir%/vigie.jsonl', $handler->getArgument('$stream'));

        $calls = $handler->getMethodCalls();
        self::assertCount(1, $calls);
        /** @var array{string, array<mixed>} $call */
        $call = $calls[0];
        [$method, $arguments] = $call;
        self::assertSame('setFormatter', $method);
        self::assertEquals(new Reference('iq2i_vigie.formatter.ecs'), $arguments[0]);

        $logger = $builder->getDefinition('iq2i_vigie.activity_logger');
        self::assertEquals(['vigie.activity', [new Reference('iq2i_vigie.default_handler')]], $logger->getArguments());
    }

    public function testOutputPathIsConfigurable(): void
    {
        $builder = $this->compiledContainer(['output' => ['path' => 'php://stdout']]);

        self::assertSame('php://stdout', $builder->getDefinition('iq2i_vigie.default_handler')->getArgument('$stream'));
    }

    public function testConfiguredHandlersAreUsedVerbatimWithoutADefaultHandler(): void
    {
        $builder = $this->compiledContainer(['output' => ['handlers' => ['app.custom_handler']]]);

        self::assertFalse($builder->hasDefinition('iq2i_vigie.default_handler'));

        $logger = $builder->getDefinition('iq2i_vigie.activity_logger');
        self::assertEquals(['vigie.activity', [new Reference('app.custom_handler')]], $logger->getArguments());
    }

    public function testInMemoryStorageIsUsedWhenConfigured(): void
    {
        $builder = $this->compiledContainer(['storage' => 'in_memory']);

        self::assertSame('iq2i_vigie.in_memory_storage', (string) $builder->getAlias(ActivityStorageInterface::class));
        self::assertTrue($builder->hasAlias(InMemoryActivityStorage::class));
        self::assertFalse($builder->hasDefinition('iq2i_vigie.default_handler'));
    }

    public function testACustomStorageServiceIdIsAliasedVerbatim(): void
    {
        $builder = $this->compiledContainer(['storage' => 'app.my_storage']);

        self::assertSame('app.my_storage', (string) $builder->getAlias(ActivityStorageInterface::class));
    }

    /**
     * A bare ContainerBuilder as a real kernel would leave it before booting a bundle: the "kernel.*"
     * parameters below are read unconditionally by Symfony's own BundleExtension/ExtensionTrait plumbing.
     */
    private function newBuilder(): ContainerBuilder
    {
        $builder = new ContainerBuilder();
        $builder->setParameter('kernel.environment', 'test');
        $builder->setParameter('kernel.debug', false);
        $builder->setParameter('kernel.build_dir', sys_get_temp_dir());
        $builder->setParameter('kernel.bundles', []);

        return $builder;
    }

    /**
     * @param array<string, mixed> $vigieConfig
     */
    private function compiledContainer(array $vigieConfig = []): ContainerBuilder
    {
        $builder = $this->newBuilder();

        $bundle = new IQ2iVigieBundle();
        $extension = $bundle->getContainerExtension();
        \assert(null !== $extension);
        $builder->registerExtension($extension);

        $builder->prependExtensionConfig('iq2i_vigie', $vigieConfig);

        $instanceof = [];
        $configurator = new ContainerConfigurator($builder, new PhpFileLoader($builder, new FileLocator(__DIR__)), $instanceof, __DIR__, 'IQ2iVigieBundleTest.php', 'test');
        $bundle->prependExtension($configurator, $builder);

        $extension->load([$vigieConfig], $builder);

        return $builder;
    }
}
