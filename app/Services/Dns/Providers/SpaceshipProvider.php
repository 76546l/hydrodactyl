<?php

namespace Pterodactyl\Services\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use Pterodactyl\Contracts\Dns\DnsProviderInterface;
use Pterodactyl\Exceptions\Dns\DnsProviderException;

/**
 * Spaceship (spaceship.dev) DNS provider.
 *
 * Spaceship's API has no per-record identifiers: records are addressed by the
 * domain in the path, and matched on name + type + value. Record identifiers
 * handed back by this provider are therefore fabricated keys of the form
 * "<TYPE>|<name>", where <name> is the zone-relative record name. For SRV the
 * name retains its "_service._protocol." prefix so that several SRV records on
 * one label stay distinguishable.
 *
 * Because the value is part of the match key, there is no way to change a
 * record's value in place; updateRecord deletes the existing record and writes
 * the replacement.
 */
class SpaceshipProvider implements DnsProviderInterface
{
    private const BASE_URI = 'https://spaceship.dev/api/v1/';

    private const PAGE_SIZE = 100;

    private const APEX = '@';

    /**
     * Value field names carried by each record type in write, list and delete
     * payloads. Spaceship uses a different set of fields per type rather than a
     * single generic content field.
     */
    private const VALUE_FIELDS = [
        'A' => ['address'],
        'AAAA' => ['address'],
        'CNAME' => ['cname'],
        'MX' => ['exchange', 'preference'],
        'TXT' => ['value'],
        'SRV' => ['service', 'protocol', 'priority', 'weight', 'port', 'target'],
    ];

    /**
     * Record types whose content is a single scalar value.
     */
    private const SCALAR_TYPES = ['A' => 'address', 'AAAA' => 'address', 'CNAME' => 'cname', 'TXT' => 'value'];

    private Client $client;

    /**
     * The domain used by testConnection(), which takes no arguments of its own.
     */
    private ?string $domain;

    public function __construct(array $config, ?string $domain = null)
    {
        $this->domain = $domain ?: ($config['domain'] ?? null);

        if (!empty($config['api_key']) && !empty($config['api_secret'])) {
            $this->client = new Client([
                'base_uri' => self::BASE_URI,
                'headers' => [
                    'X-API-Key' => $config['api_key'],
                    'X-API-Secret' => $config['api_secret'],
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                ],
                'timeout' => 30,
            ]);
        }
    }

    public function testConnection(): bool
    {
        $this->assertConfigured();

        try {
            if ($this->domain !== null) {
                // Listing the records of one domain only needs the dnsrecords:read
                // scope, so a subdomain-only key is enough to validate.
                $this->httpGet($this->recordsPath($this->domain), ['take' => 1, 'skip' => 0]);
            } else {
                // Without a domain to scope to we can only check the account itself,
                // which additionally requires the domains:read scope.
                $this->httpGet('domains', ['take' => 1, 'skip' => 0]);
            }

            return true;
        } catch (GuzzleException $e) {
            throw DnsProviderException::connectionFailed('spaceship', $this->parseErrorMessage($e));
        }
    }

    public function createRecord(string $domain, string $name, string $type, $content, int $ttl = 300): string
    {
        $this->assertConfigured();
        $type = $this->normalizeType($type);

        $keyName = $this->normalizeRecordName($domain, $name);

        try {
            $this->httpPut($this->recordsPath($domain), [
                'force' => true,
                'items' => [$this->buildRecordPayload($type, $keyName, $content, $ttl)],
            ]);
        } catch (GuzzleException $e) {
            throw DnsProviderException::recordCreationFailed($domain, $name, $this->parseErrorMessage($e));
        }

        return $this->encodeRecordId($type, $keyName);
    }

    public function updateRecord(string $domain, string $recordId, $content, ?int $ttl = null): bool
    {
        $this->assertConfigured();
        [$type, $keyName] = $this->decodeRecordId($recordId);

        try {
            $existing = $this->findRecordByKey($domain, $type, $keyName);
        } catch (GuzzleException $e) {
            throw DnsProviderException::recordUpdateFailed($domain, [$recordId], $this->parseErrorMessage($e));
        }

        if ($existing === null) {
            // Matches BunnyProvider and CloudflareProvider, which both surface a
            // missing record as a failure when updating.
            throw DnsProviderException::recordUpdateFailed($domain, [$recordId], 'record no longer exists in this zone');
        }

        $ttl ??= (int) ($existing['ttl'] ?? 300);

        try {
            // The value is part of the match key on Spaceship, so a changed value
            // can never replace an existing record in place. Remove the old record
            // first, then write the replacement.
            $this->httpDelete($this->recordsPath($domain), [$this->buildDeletePayload($existing)]);
            $this->httpPut($this->recordsPath($domain), [
                'force' => true,
                'items' => [$this->buildRecordPayload($type, $keyName, $content, $ttl, $existing)],
            ]);
        } catch (GuzzleException $e) {
            throw DnsProviderException::recordUpdateFailed($domain, [$recordId], $this->parseErrorMessage($e));
        }

        return true;
    }

    public function deleteRecord(string $domain, string $recordId): void
    {
        $this->assertConfigured();
        [$type, $keyName] = $this->decodeRecordId($recordId);

        try {
            $existing = $this->findRecordByKey($domain, $type, $keyName);

            if ($existing === null) {
                // The record was renamed or removed out of band. BunnyProvider and
                // CloudflareProvider treat an already-absent record as a no-op, and
                // the Spaceship delete endpoint reports success when nothing matches.
                return;
            }

            // Delete with the value the server currently reports: Spaceship matches
            // deletes on the record's value, and for TXT that comparison is
            // case-sensitive, so a locally reconstructed value may not match.
            $this->httpDelete($this->recordsPath($domain), [$this->buildDeletePayload($existing)]);
        } catch (GuzzleException $e) {
            throw DnsProviderException::recordDeletionFailed($domain, [$recordId], $this->parseErrorMessage($e));
        }
    }

    public function getRecord(string $domain, string $recordId): array
    {
        $this->assertConfigured();
        [$type, $keyName] = $this->decodeRecordId($recordId);

        try {
            $record = $this->findRecordByKey($domain, $type, $keyName);
        } catch (GuzzleException $e) {
            throw DnsProviderException::connectionFailed('spaceship', $this->parseErrorMessage($e));
        }

        if ($record === null) {
            throw DnsProviderException::connectionFailed('spaceship', "DNS record '{$recordId}' was not found in zone '{$domain}'.");
        }

        return $record;
    }

    public function listRecords(string $domain, ?string $name = null, ?string $type = null): array
    {
        $this->assertConfigured();

        $filterType = $type !== null ? $this->normalizeType($type) : null;
        $filterName = $name !== null ? $this->normalizeRecordName($domain, $name) : null;

        $records = [];
        $skip = 0;

        try {
            while (true) {
                $page = $this->httpGet($this->recordsPath($domain), [
                    'take' => self::PAGE_SIZE,
                    'skip' => $skip,
                ]);

                $items = $page['items'] ?? [];

                foreach ($items as $record) {
                    if ($filterType !== null && strtoupper((string) ($record['type'] ?? '')) !== $filterType) {
                        continue;
                    }

                    if ($filterName !== null && !$this->recordMatchesName($record, $filterName)) {
                        continue;
                    }

                    $records[] = $this->decorateRecord($record);
                }

                $skip += count($items);

                if ($items === [] || $skip >= (int) ($page['total'] ?? $skip)) {
                    break;
                }
            }
        } catch (GuzzleException $e) {
            throw DnsProviderException::connectionFailed('spaceship', $this->parseErrorMessage($e));
        }

        return $records;
    }

    public function getConfigurationSchema(): array
    {
        return [
            'api_key' => [
                'type' => 'string',
                'required' => true,
                'description' => 'Spaceship API Key',
                'sensitive' => true,
            ],
            'api_secret' => [
                'type' => 'string',
                'required' => true,
                'description' => 'Spaceship API Secret',
                'sensitive' => true,
            ],
        ];
    }

    public function validateConfiguration(array $config): bool
    {
        if (empty($config['api_key'])) {
            throw DnsProviderException::invalidConfiguration('spaceship', 'api_key');
        }

        if (empty($config['api_secret'])) {
            throw DnsProviderException::invalidConfiguration('spaceship', 'api_secret');
        }

        return true;
    }

    public function getSupportedRecordTypes(): array
    {
        return array_keys(self::VALUE_FIELDS);
    }

    /**
     * Build the request item for a record write.
     *
     * @param array|null $existing The record being replaced, used to recover SRV
     *                             service/protocol when they cannot be derived
     *                             from the name or the supplied content.
     */
    private function buildRecordPayload(string $type, string $keyName, $content, int $ttl, ?array $existing = null): array
    {
        $name = $keyName;
        $payload = ['type' => $type, 'ttl' => $ttl];

        if ($type === 'SRV') {
            // Spaceship builds the record's DNS label as "<service>.<protocol>.<name>",
            // so the name must not repeat the prefix it is given separately.
            [$service, $protocol, $name] = $this->splitSrvName($keyName, $content, $existing);

            $payload['name'] = $name;
            $payload['service'] = $service;
            $payload['protocol'] = $protocol;

            foreach ($this->parseSrvContent($content) as $field => $value) {
                $payload[$field] = $value;
            }

            return $payload;
        }

        $payload['name'] = $name;

        foreach ($this->parseValueContent($type, $content) as $field => $value) {
            $payload[$field] = $value;
        }

        return $payload;
    }

    /**
     * Build the delete body for a record, using the values the server reports.
     */
    private function buildDeletePayload(array $record): array
    {
        $type = strtoupper((string) ($record['type'] ?? ''));

        if (!isset(self::VALUE_FIELDS[$type])) {
            throw DnsProviderException::unsupportedRecordType('spaceship', $type);
        }

        $payload = ['type' => $type, 'name' => (string) ($record['name'] ?? '')];

        foreach (self::VALUE_FIELDS[$type] as $field) {
            if (array_key_exists($field, $record)) {
                $payload[$field] = $record[$field];
            }
        }

        return $payload;
    }

    /**
     * Extract the service and protocol for an SRV record, plus the bare label the
     * API expects in its "name" field.
     *
     * @return array{0: string, 1: string, 2: string}
     */
    private function splitSrvName(string $keyName, $content, ?array $existing): array
    {
        if (preg_match('/^(_[^.]+)\.(_[^.]+)\.(.+)$/', $keyName, $matches)) {
            return [$matches[1], $matches[2], $matches[3]];
        }

        // The caller passed a bare label, so service and protocol have to come from
        // the content (or from the record we are replacing). The subdomain features
        // spell the protocol key "proto".
        $service = is_array($content) ? ($content['service'] ?? null) : null;
        $protocol = is_array($content) ? ($content['protocol'] ?? $content['proto'] ?? null) : null;

        $service ??= $existing['service'] ?? null;
        $protocol ??= $existing['protocol'] ?? null;

        if (empty($service) || empty($protocol)) {
            throw DnsProviderException::unsupportedRecordType(
                'spaceship',
                "SRV without a service/protocol (expected a name like \"_service._protocol.{$keyName}\")"
            );
        }

        return [$this->normalizeSrvLabel((string) $service), $this->normalizeSrvLabel((string) $protocol), $keyName];
    }

    /**
     * Spaceship rejects service and protocol labels without their leading underscore.
     */
    private function normalizeSrvLabel(string $label): string
    {
        return str_starts_with($label, '_') ? $label : '_' . $label;
    }

    /**
     * Map record content onto the SRV-specific fields.
     */
    private function parseSrvContent($content): array
    {
        if (is_array($content)) {
            $parts = $content;

            // Some callers only supply the textual form.
            if (!isset($parts['target']) && isset($content['content']) && is_string($content['content'])) {
                $parts = $this->parseSrvString($content['content']);
            }
        } elseif (is_string($content)) {
            $parts = $this->parseSrvString($content);
        } else {
            $parts = [];
        }

        $fields = [];
        foreach (['priority', 'weight', 'port'] as $field) {
            if (isset($parts[$field])) {
                $fields[$field] = (int) $parts[$field];
            }
        }

        if (!isset($parts['target'])) {
            throw DnsProviderException::unsupportedRecordType('spaceship', 'SRV without a target');
        }

        $fields['target'] = (string) $parts['target'];

        return $fields;
    }

    /**
     * Parse "SRV <priority> <weight> <port> <target>" or "<priority> <weight> <port> <target>".
     */
    private function parseSrvString(string $content): array
    {
        $parts = preg_split('/\s+/', trim($content));

        if (count($parts) >= 5 && strtoupper($parts[0]) === 'SRV') {
            array_shift($parts);
        }

        if (count($parts) < 4) {
            return [];
        }

        return [
            'priority' => $parts[0],
            'weight' => $parts[1],
            'port' => $parts[2],
            'target' => $parts[3],
        ];
    }

    /**
     * Map record content onto the value field(s) for scalar, MX and CNAME records.
     */
    private function parseValueContent(string $type, $content): array
    {
        if (isset(self::SCALAR_TYPES[$type])) {
            $field = self::SCALAR_TYPES[$type];

            if (is_array($content)) {
                $value = $content[$field] ?? $content['content'] ?? $content['value'] ?? null;

                if ($value === null) {
                    throw DnsProviderException::unsupportedRecordType('spaceship', "{$type} without a {$field}");
                }

                return [$field => (string) $value];
            }

            return [$field => (string) $content];
        }

        // MX carries two fields.
        if (is_array($content)) {
            if (!isset($content['exchange'])) {
                throw DnsProviderException::unsupportedRecordType('spaceship', 'MX without an exchange');
            }

            $fields = ['exchange' => (string) $content['exchange']];

            if (isset($content['preference'])) {
                $fields['preference'] = (int) $content['preference'];
            }

            return $fields;
        }

        // Accept the textual "<preference> <exchange>" form.
        $parts = preg_split('/\s+/', trim((string) $content));

        if (count($parts) < 2 || !is_numeric($parts[0])) {
            throw DnsProviderException::unsupportedRecordType('spaceship', 'MX without a preference/exchange pair');
        }

        return ['preference' => (int) $parts[0], 'exchange' => $parts[1]];
    }

    /**
     * Add the fabricated record key and a normalised content string to a record
     * returned by the API.
     */
    private function decorateRecord(array $record): array
    {
        $type = strtoupper((string) ($record['type'] ?? ''));
        $record['type'] = $type;
        $record['record_id'] = $this->encodeRecordId($type, $this->recordKeyName($record));
        $record['content'] = $this->normalizeContent($type, $record);

        return $record;
    }

    /**
     * Rebuild the full zone-relative name of a record, including the
     * "_service._protocol." prefix Spaceship stores separately for SRV.
     */
    private function recordKeyName(array $record): string
    {
        $name = (string) ($record['name'] ?? '');

        if (strtoupper((string) ($record['type'] ?? '')) === 'SRV' && !empty($record['service']) && !empty($record['protocol'])) {
            return $record['service'] . '.' . $record['protocol'] . '.' . $name;
        }

        return $name;
    }

    /**
     * Render a record's value in the textual form the features and the update
     * rollback path expect.
     */
    private function normalizeContent(string $type, array $record): string
    {
        if (isset(self::SCALAR_TYPES[$type])) {
            return (string) ($record[self::SCALAR_TYPES[$type]] ?? '');
        }

        if ($type === 'MX') {
            return trim(($record['preference'] ?? '') . ' ' . ($record['exchange'] ?? ''));
        }

        if ($type === 'SRV') {
            return trim(
                ($record['priority'] ?? '') . ' ' . ($record['weight'] ?? '') . ' '
                . ($record['port'] ?? '') . ' ' . ($record['target'] ?? '')
            );
        }

        return '';
    }

    /**
     * Find the record matching a fabricated key, paging until it is found.
     */
    private function findRecordByKey(string $domain, string $type, string $keyName): ?array
    {
        $skip = 0;

        while (true) {
            $page = $this->httpGet($this->recordsPath($domain), [
                'take' => self::PAGE_SIZE,
                'skip' => $skip,
            ]);

            $items = $page['items'] ?? [];

            foreach ($items as $record) {
                if ($this->recordMatchesKey($record, $type, $keyName)) {
                    return $this->decorateRecord($record);
                }
            }

            $skip += count($items);

            if ($items === [] || $skip >= (int) ($page['total'] ?? $skip)) {
                return null;
            }
        }
    }

    private function recordMatchesKey(array $record, string $type, string $keyName): bool
    {
        if (strtoupper((string) ($record['type'] ?? '')) !== $type) {
            return false;
        }

        // Match either the reconstructed name or the raw stored one, so records
        // that were created outside this provider still line up.
        return strcasecmp((string) ($record['name'] ?? ''), $keyName) === 0
            || strcasecmp($this->recordKeyName($record), $keyName) === 0;
    }

    private function recordMatchesName(array $record, string $name): bool
    {
        return strcasecmp((string) ($record['name'] ?? ''), $name) === 0
            || strcasecmp($this->recordKeyName($record), $name) === 0;
    }

    /**
     * Spaceship addresses records through the domain in the path rather than by id.
     */
    private function recordsPath(string $domain): string
    {
        return 'dns/records/' . rawurlencode(rtrim(trim($domain), '.'));
    }

    /**
     * Convert a record name into the zone-relative form the API expects, where the
     * apex is "@" rather than an empty string.
     */
    private function normalizeRecordName(string $domain, string $name): string
    {
        $domain = rtrim(trim($domain), '.');
        $name = rtrim(trim($name), '.');

        if ($name === '' || $name === self::APEX) {
            return self::APEX;
        }

        if (strcasecmp($name, $domain) === 0) {
            return self::APEX;
        }

        if ($domain !== '' && str_ends_with(strtolower($name), '.' . strtolower($domain))) {
            $name = substr($name, 0, -(strlen($domain) + 1));
        }

        return $name === '' ? self::APEX : $name;
    }

    private function encodeRecordId(string $type, string $name): string
    {
        return $type . '|' . $name;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function decodeRecordId(string $recordId): array
    {
        $parts = explode('|', $recordId, 2);

        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new DnsProviderException(
                "Unrecognised record key '{$recordId}' for DNS provider 'spaceship': expected \"<TYPE>|<name>\"."
            );
        }

        return [strtoupper($parts[0]), $parts[1]];
    }

    private function normalizeType(string $type): string
    {
        $type = strtoupper($type);

        if (!isset(self::VALUE_FIELDS[$type])) {
            throw DnsProviderException::unsupportedRecordType('spaceship', $type);
        }

        return $type;
    }

    private function assertConfigured(): void
    {
        if (!isset($this->client)) {
            throw DnsProviderException::invalidConfiguration('spaceship', 'api_key');
        }
    }

    private function httpGet(string $path, array $query = []): array
    {
        $response = $this->client->get($path, ['query' => $query]);

        return $this->decodeBody($response->getBody()->getContents());
    }

    private function httpPut(string $path, array $body): void
    {
        $this->client->put($path, ['json' => $body]);
    }

    private function httpDelete(string $path, array $body): void
    {
        $this->client->delete($path, ['json' => $body]);
    }

    private function decodeBody(string $body): array
    {
        if (trim($body) === '') {
            return [];
        }

        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : [];
    }

    private function parseErrorMessage(GuzzleException $e): string
    {
        if ($e instanceof RequestException && $e->hasResponse()) {
            $response = $e->getResponse();
            $data = json_decode((string) $response->getBody(), true);

            if (is_array($data)) {
                $message = is_string($data['detail'] ?? null) ? $data['detail'] : '';

                if (isset($data['data'][0]['details'])) {
                    $details = (string) $data['data'][0]['details'];
                    $field = isset($data['data'][0]['field']) ? " ({$data['data'][0]['field']})" : '';
                    $message = trim($message . ' ' . $details . $field);
                }

                if ($message !== '') {
                    return $message;
                }
            }

            return 'DNS provider returned HTTP ' . $response->getStatusCode() . '.';
        }

        $message = $e->getMessage();

        return strlen($message) > 200 ? 'DNS service temporarily unavailable.' : $message;
    }
}
