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

use IQ2i\VigieBundle\Model\ThreatDecision;
use IQ2i\VigieBundle\Model\ThreatScope;
use IQ2i\VigieBundle\Storage\ThreatDecisionQuery;
use IQ2i\VigieBundle\Storage\ThreatDecisionStoreInterface;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\ClockInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Answers "why is this IP/session/user blocked?" without needing `cscli`
 * access from the application host — see doc/threat.md.
 */
#[AsCommand(name: 'vigie:threat:list', description: 'List locally known threat decisions')]
final class ListThreatDecisionsCommand extends Command
{
    private const FORMATS = ['table', 'json', 'csv'];

    /**
     * @var list<string>
     */
    private const EXPORT_FIELDS = [
        'provider', 'external_id', 'scope', 'value', 'type', 'origin', 'scenario', 'expires_at', 'synced_at',
    ];

    public function __construct(
        private readonly ?ThreatDecisionStoreInterface $store = null,
        private readonly ClockInterface $clock = new Clock(),
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('scope', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Filter by scope (e.g. "Ip", "Range", "Country", "AS", or a custom one such as "session"), repeatable')
            ->addOption('value', null, InputOption::VALUE_REQUIRED, 'Filter by exact value — never matches a "Range" decision by the address it covers, only by its own CIDR string')
            ->addOption('provider', null, InputOption::VALUE_REQUIRED, 'Filter by provider (e.g. "crowdsec")')
            ->addOption('active-only', null, InputOption::VALUE_NONE, 'Only decisions still active as of now — expired ones are included by default')
            ->addOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum number of decisions to return', '50')
            ->addOption('format', null, InputOption::VALUE_REQUIRED, \sprintf('Output format (%s)', implode(', ', self::FORMATS)), 'table')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        if (null === $this->store) {
            $io->error('No threat decision store is configured. Set "iq2i_vigie.threat.storage" (see doc/threat.md).');

            return Command::FAILURE;
        }

        /** @var string $format */
        $format = $input->getOption('format');

        if (!\in_array($format, self::FORMATS, true)) {
            $io->error(\sprintf('Unknown format "%s". Available formats: %s.', $format, implode(', ', self::FORMATS)));

            return Command::INVALID;
        }

        try {
            $query = $this->createQuery($input);
        } catch (\InvalidArgumentException $e) {
            $io->error($e->getMessage());

            return Command::INVALID;
        }

        $decisions = $this->store->find($query);

        match ($format) {
            'json' => $this->renderJson($output, $decisions),
            'csv' => $this->renderCsv($output, $decisions),
            default => $this->renderTable($io, $decisions, $this->store->count($query)),
        };

        return Command::SUCCESS;
    }

    private function createQuery(InputInterface $input): ThreatDecisionQuery
    {
        /** @var list<string> $rawScopes */
        $rawScopes = $input->getOption('scope');

        /** @var ?string $value */
        $value = $input->getOption('value');

        /** @var ?string $provider */
        $provider = $input->getOption('provider');

        $limit = InputParser::int($input, 'limit', 1, 1000) ?? throw new \InvalidArgumentException('Option "--limit" must not be empty.');

        $scopes = array_map(ThreatScope::of(...), $rawScopes);

        // Stored values are normalized per scope (see ThreatScope::normalizeValue()),
        // so "--scope Country --value fr" has to look up "FR".
        if (null !== $value && 1 === \count($scopes)) {
            $value = $scopes[0]->normalizeValue($value);
        }

        return new ThreatDecisionQuery(
            scopes: $scopes,
            value: $value,
            provider: $provider,
            activeAt: $input->getOption('active-only') ? $this->clock->now() : null,
            limit: $limit,
        );
    }

    /**
     * @param list<ThreatDecision> $decisions
     */
    private function renderTable(SymfonyStyle $io, array $decisions, int $total): void
    {
        $io->table(
            ['Provider', 'Scope', 'Value', 'Type', 'Origin', 'Scenario', 'Expires at'],
            array_map(static fn (ThreatDecision $decision): array => [
                $decision->provider,
                $decision->scope->value,
                $decision->value,
                $decision->type,
                $decision->origin ?? '-',
                $decision->scenario ?? '-',
                $decision->expiresAt?->format('Y-m-d H:i:s') ?? 'never',
            ], $decisions),
        );

        $io->writeln(\sprintf('<info>%d</info> decision%s shown out of <info>%d</info>.', \count($decisions), 1 === \count($decisions) ? '' : 's', $total));
    }

    /**
     * @param list<ThreatDecision> $decisions
     */
    private function renderJson(OutputInterface $output, array $decisions): void
    {
        $data = array_map(self::row(...), $decisions);

        $output->writeln((string) json_encode($data, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES | \JSON_THROW_ON_ERROR));
    }

    /**
     * @param list<ThreatDecision> $decisions
     */
    private function renderCsv(OutputInterface $output, array $decisions): void
    {
        $stream = fopen('php://memory', 'r+');

        if (false === $stream) {
            throw new \RuntimeException('Unable to open in-memory stream.');
        }

        CsvWriter::writeRow($stream, self::EXPORT_FIELDS);

        foreach ($decisions as $decision) {
            CsvWriter::writeRow($stream, array_values(self::row($decision)));
        }

        rewind($stream);
        $csv = stream_get_contents($stream);
        fclose($stream);

        $output->write(false !== $csv ? $csv : '');
    }

    /**
     * @return array{provider: string, external_id: string, scope: string, value: string, type: string, origin: ?string, scenario: ?string, expires_at: ?string, synced_at: string}
     */
    private static function row(ThreatDecision $decision): array
    {
        return [
            'provider' => $decision->provider,
            'external_id' => $decision->externalId,
            'scope' => $decision->scope->value,
            'value' => $decision->value,
            'type' => $decision->type,
            'origin' => $decision->origin,
            'scenario' => $decision->scenario,
            'expires_at' => $decision->expiresAt?->format(\DateTimeInterface::ATOM),
            'synced_at' => $decision->syncedAt->format(\DateTimeInterface::ATOM),
        ];
    }
}
