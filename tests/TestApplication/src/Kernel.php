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

namespace IQ2i\VigieBundle\Tests\TestApplication;

use IQ2i\VigieBundle\IQ2iVigieBundle;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\CsrfController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\CustomActivityController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\FailingController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\ForbiddenController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\PingController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\PlainController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\SecurityController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\SubjectController;
use IQ2i\VigieBundle\Tests\TestApplication\Controller\UntrackedController;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Bundle\WebProfilerBundle\WebProfilerBundle;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Kernel as SymfonyKernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

final class Kernel extends SymfonyKernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();

        yield new IQ2iVigieBundle();

        // Only the "security" test environment needs a real firewall stack
        // (SecurityFlowTest): every other environment leaves SecurityBundle
        // out entirely, closer to how most agency projects run it.
        if ('security' === $this->getEnvironment()) {
            yield new SecurityBundle();
        }

        // Only the "profiler" test environment needs Twig/WebProfilerBundle
        // (ProfilerTest): every other environment runs without them, since
        // the bundle itself requires neither.
        if ('profiler' === $this->getEnvironment()) {
            yield new TwigBundle();
            yield new WebProfilerBundle();
        }
    }

    public function getCacheDir(): string
    {
        // Keep the cache dir unique per process, so the container cache invalidates when a bundle source file changes between test runs.
        return sys_get_temp_dir().'/vigie/tests/var/'.$this->getEnvironment().'/cache/'.getmypid();
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/vigie/tests/var/'.$this->getEnvironment().'/log';
    }

    public function getProjectDir(): string
    {
        return \dirname(__DIR__);
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('app_ping', '/ping')->controller(PingController::class);
        $routes->add('app_plain', '/plain')->controller(PlainController::class);
        $routes->add('app_untracked', '/untracked')->controller(UntrackedController::class);
        $routes->add('app_subject', '/subjects/{id}')->controller(SubjectController::class);
        $routes->add('app_failing', '/failing')->controller(FailingController::class);

        if ('processors' === $this->getEnvironment()) {
            $routes->add('app_custom_activity', '/custom-activity')->controller(CustomActivityController::class);
        }

        if ('csrf' === $this->getEnvironment()) {
            $routes->add('app_csrf', '/csrf')->controller(CsrfController::class)->methods(['POST']);
        }

        if ('security' === $this->getEnvironment()) {
            $routes->add('app_protected', '/protected')->controller([SecurityController::class, 'protectedAction']);
            $routes->add('app_forbidden', '/protected/forbidden')->controller(ForbiddenController::class);
            // SecurityBundle's logout listener only intercepts "/logout" if
            // a matching route exists; this micro kernel has no router
            // import mechanism for it otherwise.
            $routes->import('security.route_loader.logout', 'service');
        }

        if ('profiler' === $this->getEnvironment()) {
            // Symfony 6.4 ships these as .xml, later versions as .php: glob
            // both so the test app boots against the whole supported range.
            $routes->import('@WebProfilerBundle/Resources/config/routing/wdt.*', 'glob')->prefix('/_wdt');
            $routes->import('@WebProfilerBundle/Resources/config/routing/profiler.*', 'glob')->prefix('/_profiler');
        }

        if ('threat_enforce' === $this->getEnvironment()) {
            // The captcha redirect target: excluded from enforcement by its
            // own name in threat.enforce.remediations, not by any attribute
            // of its own.
            $routes->add('app_captcha', '/captcha')->controller(PlainController::class);
        }

        if ('threat_ingest' === $this->getEnvironment()) {
            // Imported with a prefix, the way an application would import
            // "@IQ2iVigieBundle/config/routes.php" of its own — see
            // doc/threat.md.
            $routes->import('@IQ2iVigieBundle/config/routes.php')->prefix('/vigie');
        }
    }

    protected function configureContainer(ContainerBuilder $containerBuilder, LoaderInterface $loader): void
    {
        $loader->load($this->getProjectDir().'/config/{packages}/*.php', 'glob');
        $loader->load($this->getProjectDir().'/config/{packages}/'.$this->getEnvironment().'/*.php', 'glob');
        $loader->load($this->getProjectDir().'/config/{services}.php', 'glob');
        $loader->load($this->getProjectDir().'/config/{services}_'.$this->getEnvironment().'.php', 'glob');
    }
}
