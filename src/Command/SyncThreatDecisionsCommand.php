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

namespace IQ2i\VigieBundle\Command;

use IQ2i\VigieBundle\Threat\ThreatProviderException;
use IQ2i\VigieBundle\Threat\ThreatSynchronizer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Command\LockableTrait;
use Symfony\Component\Console\Command\SignalableCommandInterface;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Lock\Store\SemaphoreStore;

#[AsCommand(name: 'vigie:threat:sync', description: "Pull the configured SIEM's decisions into the local threat store")]
final class SyncThreatDecisionsCommand extends Command implements SignalableCommandInterface
{
    use LockableTrait;

    private bool $stopping = false;

    /**
     * @var \Closure(int): void
     */
    private readonly \Closure $sleep;

    /**
     * @param ?\Closure(int): void $sleep overridable in tests, so --watch's loop doesn't have to
     *                                    sleep for real seconds to be exercised
     */
    public function __construct(
        private readonly ThreatSynchronizer $synchronizer,
        ?\Closure $sleep = null,
    ) {
        parent::__construct();

        $this->sleep = $sleep ?? static function (int $seconds): void {
            sleep($seconds);
        };
    }

    protected function configure(): void
    {
        $this
            ->addOption('startup', null, InputOption::VALUE_NONE, 'Force a full resync of every currently active decision instead of a delta (use it after the local store was wiped or restored)')
            ->addOption('no-purge', null, InputOption::VALUE_NONE, 'Skip purging locally expired decisions at the end of this run')
            ->addOption('watch', null, InputOption::VALUE_NONE, 'Keep running, pulling a delta sync every --interval seconds instead of exiting after one; SIGTERM/SIGINT stop it cleanly')
            ->addOption('interval', null, InputOption::VALUE_REQUIRED, 'Seconds to wait between two syncs in --watch mode', '2')
        ;
    }

    /**
     * @return list<int>
     */
    public function getSubscribedSignals(): array
    {
        return [\SIGTERM, \SIGINT];
    }

    public function handleSignal(int $signal, int|false $previousExitCode = 0): int|false
    {
        // Let the loop in execute() finish the sync it's currently running (or currently sleeping
        // between two) and return normally, rather than tearing down mid-applyBatch().
        $this->stopping = true;

        return false;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $watch = (bool) $input->getOption('watch');

        try {
            $interval = InputParser::int($input, 'interval', 1, 3600) ?? 2;
        } catch (\InvalidArgumentException $e) {
            $io->error($e->getMessage());

            return Command::INVALID;
        }

        // symfony/lock is an optional dependency: without it, this guards nothing.
        // The lock only ever protects a single host, not a fleet running this command on several,
        // and covers the whole --watch session, not each iteration of it.
        $locking = class_exists(SemaphoreStore::class);

        if ($locking && !$this->lock()) {
            $io->note('Another vigie:threat:sync is already running on this host, skipping this run.');

            return Command::SUCCESS;
        }

        // Only the first iteration honors --startup; a resync forced on every iteration would
        // replay every currently active decision each time around instead of pulling a delta.
        $forceStartup = (bool) $input->getOption('startup');

        try {
            do {
                $status = $this->syncOnce($input, $io, $forceStartup, $watch);

                if (Command::SUCCESS !== $status) {
                    return $status;
                }

                $forceStartup = false;

                if (!$watch || $this->stopping) {
                    break;
                }

                ($this->sleep)($interval);
            } while (!$this->stopping);
        } finally {
            if ($locking) {
                $this->release();
            }
        }

        return Command::SUCCESS;
    }

    private function syncOnce(InputInterface $input, SymfonyStyle $io, bool $forceStartup, bool $watch): int
    {
        try {
            $report = $this->synchronizer->sync(
                forceStartup: $forceStartup,
                purge: !(bool) $input->getOption('no-purge'),
            );
        } catch (\LogicException|ThreatProviderException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        // In --watch mode, an iteration that changed nothing stays silent, so a long-running
        // process doesn't fill its log with identical "0 added, 0 removed" lines.
        $quiet = $watch && !$report['startup'] && 0 === $report['added'] && 0 === $report['removed'] && 0 === $report['skipped'] && 0 === $report['purged'];

        if (!$quiet) {
            $io->writeln(\sprintf(
                '<info>%s</info>: %s sync, %d added, %d removed, %d skipped, %d purged.',
                $report['provider'],
                $report['startup'] ? 'startup' : 'delta',
                $report['added'],
                $report['removed'],
                $report['skipped'],
                $report['purged'],
            ));

            if ($report['skipped'] > 0) {
                $io->note(\sprintf('%d decision(s) could not be read and were skipped. See the "vigie" log channel.', $report['skipped']));
            }
        }

        return Command::SUCCESS;
    }
}
