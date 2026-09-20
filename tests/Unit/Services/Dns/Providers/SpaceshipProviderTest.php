<?php

namespace Pterodactyl\Tests\Unit\Services\Dns\Providers;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Pterodactyl\Exceptions\Dns\DnsProviderException;
use Pterodactyl\Services\Dns\Providers\SpaceshipProvider;
use Pterodactyl\Tests\TestCase;
use ReflectionProperty;

class SpaceshipProviderTest extends TestCase
{
    private const DOMAIN = 'example.com';
    private const API_KEY = 'test-api-key';
    private const API_SECRET = 'test-api-secret';

    /**
     * Recorded requests, newest last.
     */
    private array $history = [];

    /**
     * Build a provider whose transport is mocked, keeping the client the provider
     * itself constructed so the credentials and headers are the real ones.
     */
    private function makeProvider(array $responses, ?string $domain = self::DOMAIN): SpaceshipProvider
    {
        $provider = new SpaceshipProvider([
            'api_key' => self::API_KEY,
            'api_secret' => self::API_SECRET,
        ], $domain);

        $property = new ReflectionProperty(SpaceshipProvider::class, 'client');
        $configured = $property->getValue($provider);

        $this->history = [];
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($this->history));

        $property->setValue($provider, new Client([
            'base_uri' => $configured->getConfig('base_uri'),
            'headers' => $configured->getConfig('headers'),
            'handler' => $stack,
        ]));

        return $provider;
    }

    private function jsonResponse(array $body, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($body));
    }

    private function recordList(array $items, ?int $total = null): Response
    {
        return $this->jsonResponse(['items' => $items, 'total' => $total ?? count($items)]);
    }

    private function sentRequest(int $index): Request
    {
        return $this->history[$index]['request'];
    }

    private function sentBody(int $index): array
    {
        return json_decode((string) $this->sentRequest($index)->getBody(), true) ?? [];
    }

    private function sentQuery(int $index): array
    {
        parse_str($this->sentRequest($index)->getUri()->getQuery(), $query);

        return $query;
    }

    public function testCreateRecordPutsASingleItemAndReturnsAFabricatedKey()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $key = $provider->createRecord(self::DOMAIN, 'mc', 'A', '203.0.113.10', 300);

        $this->assertSame('A|mc', $key);

        $request = $this->sentRequest(0);
        $this->assertSame('PUT', $request->getMethod());
        $this->assertSame('/api/v1/dns/records/example.com', $request->getUri()->getPath());

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'A',
                'ttl' => 300,
                'name' => 'mc',
                'address' => '203.0.113.10',
            ]],
        ], $this->sentBody(0));
    }

    public function testCreateRecordSendsTheApiKeyAndSecretHeadersVerbatim()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $provider->createRecord(self::DOMAIN, 'mc', 'A', '203.0.113.10');

        $request = $this->sentRequest(0);
        $this->assertSame(self::API_KEY, $request->getHeaderLine('X-API-Key'));
        $this->assertSame(self::API_SECRET, $request->getHeaderLine('X-API-Secret'));
    }

    public function testCreateRecordUsesTheValueFieldForTxtRecords()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $provider->createRecord(self::DOMAIN, 'txtprobe', 'TXT', 'hello world', 120);

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'TXT',
                'ttl' => 120,
                'name' => 'txtprobe',
                'value' => 'hello world',
            ]],
        ], $this->sentBody(0));
    }

    public function testCreateRecordSendsBothMxFields()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $provider->createRecord(self::DOMAIN, '@', 'MX', ['exchange' => 'mail.example.com', 'preference' => 10]);

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'MX',
                'ttl' => 300,
                'name' => '@',
                'exchange' => 'mail.example.com',
                'preference' => 10,
            ]],
        ], $this->sentBody(0));
    }

    /**
     * Spaceship labels an SRV record "<service>.<protocol>.<name>", so the prefix
     * has to be lifted out of the name rather than repeated inside it.
     */
    public function testCreateRecordLiftsTheServiceAndProtocolOutOfAnSrvName()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $key = $provider->createRecord(self::DOMAIN, '_minecraft._tcp.mc', 'SRV', [
            'service' => '_minecraft',
            'proto' => '_tcp',
            'priority' => 0,
            'weight' => 5,
            'port' => 25565,
            'target' => 'mc.example.com',
            'content' => 'SRV 0 5 25565 mc.example.com',
        ]);

        $this->assertSame('SRV|_minecraft._tcp.mc', $key);

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'SRV',
                'ttl' => 300,
                'name' => 'mc',
                'service' => '_minecraft',
                'protocol' => '_tcp',
                'priority' => 0,
                'weight' => 5,
                'port' => 25565,
                'target' => 'mc.example.com',
            ]],
        ], $this->sentBody(0));
    }

    public function testCreateRecordAcceptsATextualSrvContentString()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $provider->createRecord(self::DOMAIN, 'mc', 'SRV', [
            'service' => 'ts3',
            'proto' => 'udp',
            'content' => 'SRV 0 5 9987 mc.example.com',
        ]);

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'SRV',
                'ttl' => 300,
                'name' => 'mc',
                'service' => '_ts3',
                'protocol' => '_udp',
                'priority' => 0,
                'weight' => 5,
                'port' => 9987,
                'target' => 'mc.example.com',
            ]],
        ], $this->sentBody(0));
    }

    public function testCreateRecordRejectsAnSrvRecordWithoutAService()
    {
        $provider = $this->makeProvider([]);

        $this->expectException(DnsProviderException::class);

        $provider->createRecord(self::DOMAIN, 'mc', 'SRV', ['port' => 25565, 'target' => 'mc.example.com']);
    }

    /**
     * A single subdomain can carry several SRV records, so the fabricated keys
     * must not collapse onto the same label.
     */
    public function testCreateRecordKeepsSiblingSrvRecordsDistinct()
    {
        $provider = $this->makeProvider([new Response(204), new Response(204)]);

        $primary = $provider->createRecord(self::DOMAIN, '_ts3._udp.mc', 'SRV', [
            'service' => '_ts3',
            'protocol' => '_udp',
            'priority' => 0,
            'weight' => 5,
            'port' => 9987,
            'target' => 'mc.example.com',
        ]);

        $tsdns = $provider->createRecord(self::DOMAIN, '_tsdns._tcp.mc', 'SRV', [
            'service' => '_tsdns',
            'protocol' => '_tcp',
            'priority' => 0,
            'weight' => 5,
            'port' => 41144,
            'target' => 'mc.example.com',
        ]);

        $this->assertSame('SRV|_ts3._udp.mc', $primary);
        $this->assertSame('SRV|_tsdns._tcp.mc', $tsdns);
        $this->assertNotSame($primary, $tsdns);
    }

    public function testCreateRecordNormalizesTheApexName()
    {
        $provider = $this->makeProvider([new Response(204)]);

        $provider->createRecord(self::DOMAIN, 'example.com.', 'A', '203.0.113.10');

        $this->assertSame('@', $this->sentBody(0)['items'][0]['name']);
    }

    public function testCreateRecordRejectsUnsupportedRecordTypes()
    {
        $provider = $this->makeProvider([]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage("does not support record type 'NS'");

        $provider->createRecord(self::DOMAIN, '@', 'NS', 'ns1.example.com');
    }

    /**
     * Listing a domain's records only needs the dnsrecords:read scope, so a
     * provider that knows its domain should never touch the domains endpoint.
     */
    public function testTestConnectionListsDomainRecordsWhenTheDomainIsKnown()
    {
        $provider = $this->makeProvider([$this->recordList([])]);

        $this->assertTrue($provider->testConnection());

        $request = $this->sentRequest(0);
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame('/api/v1/dns/records/example.com', $request->getUri()->getPath());
        $this->assertSame(['take' => '1', 'skip' => '0'], $this->sentQuery(0));
    }

    public function testTestConnectionFallsBackToTheDomainsListingWithoutADomain()
    {
        $provider = $this->makeProvider([$this->recordList([])], null);

        $this->assertTrue($provider->testConnection());

        $this->assertSame('/api/v1/domains', $this->sentRequest(0)->getUri()->getPath());
    }

    public function testTestConnectionThrowsWhenTheCredentialsAreMissing()
    {
        $provider = new SpaceshipProvider(['api_key' => '', 'api_secret' => '']);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage("missing or invalid field 'api_key'");

        $provider->testConnection();
    }

    public function testTestConnectionSurfacesTheProviderErrorMessage()
    {
        $provider = $this->makeProvider([
            $this->jsonResponse(['detail' => 'Unauthorized'], 401),
        ]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage('Unauthorized');

        $provider->testConnection();
    }

    public function testListRecordsReturnsTheFabricatedKeyAndNormalizedContent()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 300, 'group' => ['type' => 'custom']],
            ]),
        ]);

        $records = $provider->listRecords(self::DOMAIN);

        $this->assertCount(1, $records);
        $this->assertSame('A|mc', $records[0]['record_id']);
        $this->assertSame('203.0.113.10', $records[0]['content']);
        $this->assertSame(300, $records[0]['ttl']);
    }

    public function testListRecordsRebuildsTheSrvNameAndContent()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                [
                    'service' => '_minecraft', 'protocol' => '_tcp', 'priority' => 0, 'weight' => 5,
                    'port' => 25565, 'target' => 'mc.example.com', 'name' => 'mc',
                    'type' => 'SRV', 'ttl' => 300,
                ],
            ]),
        ]);

        $records = $provider->listRecords(self::DOMAIN);

        $this->assertSame('SRV|_minecraft._tcp.mc', $records[0]['record_id']);
        $this->assertSame('0 5 25565 mc.example.com', $records[0]['content']);
    }

    public function testListRecordsFiltersByNameAndType()
    {
        $items = [
            ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 300],
            ['address' => '203.0.113.11', 'name' => 'other', 'type' => 'A', 'ttl' => 300],
            ['value' => 'token', 'name' => 'mc', 'type' => 'TXT', 'ttl' => 300],
        ];

        // Each call needs its own response: reading a PSR-7 body consumes it.
        $provider = $this->makeProvider([$this->recordList($items), $this->recordList($items)]);

        $this->assertSame(['A|mc'], array_column($provider->listRecords(self::DOMAIN, 'mc', 'A'), 'record_id'));
        $this->assertSame(['TXT|mc'], array_column($provider->listRecords(self::DOMAIN, null, 'TXT'), 'record_id'));
    }

    public function testListRecordsPagesUntilTheTotalIsReached()
    {
        $page = static fn (int $offset, int $count) => array_map(
            static fn (int $i) => ['address' => "203.0.113.{$i}", 'name' => "host{$i}", 'type' => 'A', 'ttl' => 300],
            range($offset, $offset + $count - 1)
        );

        $provider = $this->makeProvider([
            $this->recordList($page(0, 100), 150),
            $this->recordList($page(100, 50), 150),
        ]);

        $records = $provider->listRecords(self::DOMAIN);

        $this->assertCount(150, $records);
        $this->assertSame(['take' => '100', 'skip' => '0'], $this->sentQuery(0));
        $this->assertSame(['take' => '100', 'skip' => '100'], $this->sentQuery(1));
    }

    public function testListRecordsThrowsWhenTheZoneCannotBeRead()
    {
        $provider = $this->makeProvider([
            $this->jsonResponse([
                'detail' => 'Request validation error.',
                'data' => [['details' => 'The domain is invalid', 'field' => 'domain']],
            ], 422),
        ]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage('The domain is invalid (domain)');

        $provider->listRecords(self::DOMAIN);
    }

    public function testGetRecordFindsTheRecordBehindAFabricatedKey()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['address' => '203.0.113.11', 'name' => 'other', 'type' => 'A', 'ttl' => 300],
                ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 300],
            ]),
        ]);

        $record = $provider->getRecord(self::DOMAIN, 'A|mc');

        $this->assertSame('203.0.113.10', $record['address']);
        $this->assertSame('A|mc', $record['record_id']);
        $this->assertSame('203.0.113.10', $record['content']);
    }

    /**
     * Two SRV records can share a label, so a lookup has to separate them on the
     * service and protocol carried by the key.
     */
    public function testGetRecordSeparatesSrvRecordsThatShareALabel()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                [
                    'service' => '_ts3', 'protocol' => '_udp', 'priority' => 0, 'weight' => 5,
                    'port' => 9987, 'target' => 'mc.example.com', 'name' => 'mc', 'type' => 'SRV', 'ttl' => 300,
                ],
                [
                    'service' => '_tsdns', 'protocol' => '_tcp', 'priority' => 0, 'weight' => 5,
                    'port' => 41144, 'target' => 'mc.example.com', 'name' => 'mc', 'type' => 'SRV', 'ttl' => 300,
                ],
            ]),
        ]);

        $record = $provider->getRecord(self::DOMAIN, 'SRV|_tsdns._tcp.mc');

        $this->assertSame(41144, $record['port']);
    }

    public function testGetRecordThrowsWhenTheKeyMatchesNothing()
    {
        $provider = $this->makeProvider([$this->recordList([])]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage("DNS record 'A|mc' was not found in zone 'example.com'");

        $provider->getRecord(self::DOMAIN, 'A|mc');
    }

    public function testGetRecordRejectsAMalformedKey()
    {
        $provider = $this->makeProvider([]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage("Unrecognised record key 'not-a-key'");

        $provider->getRecord(self::DOMAIN, 'not-a-key');
    }

    /**
     * Spaceship carries the value inside the match key, so a changed value cannot
     * replace a record in place: the old record has to go first.
     */
    public function testUpdateRecordDeletesTheExistingRecordAndWritesTheReplacement()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 300],
            ]),
            new Response(204),
            new Response(204),
        ]);

        $this->assertTrue($provider->updateRecord(self::DOMAIN, 'A|mc', '198.51.100.7', 600));

        $delete = $this->sentRequest(1);
        $this->assertSame('DELETE', $delete->getMethod());
        $this->assertSame('/api/v1/dns/records/example.com', $delete->getUri()->getPath());
        $this->assertSame([[
            'type' => 'A',
            'name' => 'mc',
            'address' => '203.0.113.10',
        ]], $this->sentBody(1));

        $put = $this->sentRequest(2);
        $this->assertSame('PUT', $put->getMethod());
        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'A',
                'ttl' => 600,
                'name' => 'mc',
                'address' => '198.51.100.7',
            ]],
        ], $this->sentBody(2));
    }

    public function testUpdateRecordKeepsTheExistingTtlWhenNoneIsGiven()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 900],
            ]),
            new Response(204),
            new Response(204),
        ]);

        $provider->updateRecord(self::DOMAIN, 'A|mc', '198.51.100.7');

        $this->assertSame(900, $this->sentBody(2)['items'][0]['ttl']);
    }

    /**
     * The rollback path in SubdomainManagementService feeds a record's "content"
     * back into updateRecord, so it has to round-trip for SRV.
     */
    public function testUpdateRecordRoundTripsAnSrvContentString()
    {
        $srv = static fn () => [
            [
                'service' => '_minecraft', 'protocol' => '_tcp', 'priority' => 0, 'weight' => 5,
                'port' => 25565, 'target' => 'mc.example.com', 'name' => 'mc', 'type' => 'SRV', 'ttl' => 300,
            ],
        ];

        // One listing for getRecord, one for the update's own lookup.
        $provider = $this->makeProvider([
            $this->recordList($srv()),
            $this->recordList($srv()),
            new Response(204),
            new Response(204),
        ]);

        $record = $provider->getRecord(self::DOMAIN, 'SRV|_minecraft._tcp.mc');
        $provider->updateRecord(self::DOMAIN, 'SRV|_minecraft._tcp.mc', $record['content'], 120);

        $this->assertSame([
            'force' => true,
            'items' => [[
                'type' => 'SRV',
                'ttl' => 120,
                'name' => 'mc',
                'service' => '_minecraft',
                'protocol' => '_tcp',
                'priority' => 0,
                'weight' => 5,
                'port' => 25565,
                'target' => 'mc.example.com',
            ]],
        ], $this->sentBody(3));
    }

    public function testUpdateRecordThrowsWhenTheRecordNoLongerExists()
    {
        $provider = $this->makeProvider([$this->recordList([])]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage('record no longer exists in this zone');

        $provider->updateRecord(self::DOMAIN, 'A|mc', '198.51.100.7');
    }

    /**
     * Spaceship matches deletes on the record's value, and that comparison is
     * case-sensitive for TXT, so the value has to come back from the server
     * rather than being rebuilt locally.
     */
    public function testDeleteRecordSendsTheValueTheServerReports()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['value' => 'Hello World', 'name' => 'caseprobe', 'type' => 'TXT', 'ttl' => 300],
            ]),
            new Response(204),
        ]);

        $provider->deleteRecord(self::DOMAIN, 'TXT|caseprobe');

        $delete = $this->sentRequest(1);
        $this->assertSame('DELETE', $delete->getMethod());
        $this->assertSame('/api/v1/dns/records/example.com', $delete->getUri()->getPath());

        // A raw JSON array, not wrapped in "items".
        $this->assertSame([[
            'type' => 'TXT',
            'name' => 'caseprobe',
            'value' => 'Hello World',
        ]], $this->sentBody(1));
    }

    public function testDeleteRecordSendsEverySrvField()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                [
                    'service' => '_minecraft', 'protocol' => '_tcp', 'priority' => 0, 'weight' => 5,
                    'port' => 25565, 'target' => 'mc.example.com', 'name' => 'mc', 'type' => 'SRV', 'ttl' => 300,
                ],
            ]),
            new Response(204),
        ]);

        $provider->deleteRecord(self::DOMAIN, 'SRV|_minecraft._tcp.mc');

        $this->assertSame([[
            'type' => 'SRV',
            'name' => 'mc',
            'service' => '_minecraft',
            'protocol' => '_tcp',
            'priority' => 0,
            'weight' => 5,
            'port' => 25565,
            'target' => 'mc.example.com',
        ]], $this->sentBody(1));
    }

    public function testDeleteRecordDoesNothingWhenTheRecordIsAlreadyGone()
    {
        $provider = $this->makeProvider([$this->recordList([])]);

        $provider->deleteRecord(self::DOMAIN, 'A|mc');

        // Only the listing request was made.
        $this->assertCount(1, $this->history);
        $this->assertSame('GET', $this->sentRequest(0)->getMethod());
    }

    public function testDeleteRecordSurfacesProviderRejections()
    {
        $provider = $this->makeProvider([
            $this->recordList([
                ['address' => '203.0.113.10', 'name' => 'mc', 'type' => 'A', 'ttl' => 300],
            ]),
            $this->jsonResponse(['detail' => 'Unable to find a requested resource.'], 404),
        ]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage('Unable to find a requested resource.');

        $provider->deleteRecord(self::DOMAIN, 'A|mc');
    }

    public function testGetConfigurationSchemaMarksBothCredentialsSensitive()
    {
        $schema = (new SpaceshipProvider([]))->getConfigurationSchema();

        $this->assertSame(['api_key', 'api_secret'], array_keys($schema));

        foreach (['api_key', 'api_secret'] as $field) {
            $this->assertTrue($schema[$field]['required']);
            $this->assertTrue($schema[$field]['sensitive']);
        }
    }

    public function testValidateConfigurationRequiresBothCredentials()
    {
        $provider = new SpaceshipProvider([]);

        $this->assertTrue($provider->validateConfiguration([
            'api_key' => self::API_KEY,
            'api_secret' => self::API_SECRET,
        ]));
    }

    public function testValidateConfigurationRejectsAMissingSecret()
    {
        $provider = new SpaceshipProvider([]);

        $this->expectException(DnsProviderException::class);
        $this->expectExceptionMessage("missing or invalid field 'api_secret'");

        $provider->validateConfiguration(['api_key' => self::API_KEY]);
    }

    public function testSupportedRecordTypesAreTheVerifiedSet()
    {
        $this->assertSame(
            ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV'],
            (new SpaceshipProvider([]))->getSupportedRecordTypes()
        );
    }
}
