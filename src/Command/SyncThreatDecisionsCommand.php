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
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(name: 'vigie:threat:sync', description: "Pull the configured SIEM's decisions into the local threat store")]
final class SyncThreatDecisionsCommand extends Command
{
    public function __construct(
        private readonly ThreatSynchronizer $synchronizer,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('startup', null, InputOption::VALUE_NONE, 'Force a full resync of every currently active decision instead of a delta — use it after the local store was wiped, restored, or pointed at a different SIEM environment')
            ->addOption('no-purge', null, InputOption::VALUE_NONE, 'Skip purging locally expired decisions at the end of this run')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        try {
            $report = $this->synchronizer->sync(
                forceStartup: (bool) $input->getOption('startup'),
                purge: !(bool) $input->getOption('no-purge'),
            );
        } catch (\LogicException|ThreatProviderException $e) {
            $io->error($e->getMessage());

            return Command::FAILURE;
        }

        $io->writeln(\sprintf(
            '<info>%s</info>: %s sync — %d added, %d removed, %d skipped, %d purged.',
            $report['provider'],
            $report['startup'] ? 'startup' : 'delta',
            $report['added'],
            $report['removed'],
            $report['skipped'],
            $report['purged'],
        ));

        if ($report['skipped'] > 0) {
            $io->note(\sprintf('%d decision(s) could not be read and were skipped — see the "vigie" log channel.', $report['skipped']));
        }

        return Command::SUCCESS;
    }
}
