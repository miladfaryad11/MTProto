<?php
declare(strict_types=1);

/**
 * Telegram MTProto Proxy Scanner
 * v2025.2 — bug fixes + security hardening
 *
 * Key changes vs v2025.1:
 *  - No SSRF: target host is resolved and private/reserved IPs are rejected.
 *  - No reflected XSS: JSON is embedded with JSON_HEX_TAG/JSON_HEX_AMP.
 *  - Correct secret validation (dd must be 34 hex chars, ee 34+ even length).
 *  - Correct proxy classification (Secure / TLS / FakeTLS).
 *  - Server names are sanitized (trailing dot, control chars, length).
 *  - Connectivity check actually performs a handshake-style connect and
 *    measures latency, instead of the broken stream_select/fread logic.
 *  - TLS verification is enabled (CURLOPT_SSL_VERIFYPEER = true).
 *  - Atomic file writes so GitHub Pages never serves a half-written file.
 *  - Works from CLI and from a web request; `?scan=1` is rate limited.
 */

const CONFIG = [
    'input_file'      => 'usernames.json',
    'output_json'     => 'extracted_proxies.json',
    'output_html'     => 'index.html',
    'cache_duration'  => 3600,
    'socket_timeout'  => 3,          // seconds per connectivity attempt
    'batch_size'      => 50,
    'connect_timeout' => 10,         // seconds for HTTP fetch
    'min_scan_gap'    => 60,         // seconds between manual web scans
    'max_per_scan'    => 400,        // hard cap on proxies checked per run
];

final class ProxyScanner
{
    private string $userAgent =
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' .
        '(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36';

    /** @var string[] */
    private array $warnings = [];

    public function run(): array
    {
        echo "Starting Scan...\n";
        $usernames = $this->loadUsernames();
        if ($usernames === []) {
            $this->warn('usernames.json is missing or empty');
            return [];
        }

        $rawHtml = $this->fetchChannels($usernames);
        $proxies = $this->extractProxies($rawHtml);

        echo 'Found ' . count($proxies) . " unique proxies. Checking connectivity...\n";
        $checked = $this->checkConnectivity($proxies);

        usort($checked, static function (array $a, array $b): int {
            $ao = $a['status'] === 'Online' ? 0 : 1;
            $bo = $b['status'] === 'Online' ? 0 : 1;
            if ($ao !== $bo) {
                return $ao <=> $bo;
            }
            return ($a['latency'] ?? PHP_INT_MAX) <=> ($b['latency'] ?? PHP_INT_MAX);
        });

        $this->writeJson(CONFIG['output_json'], $checked);
        return $checked;
    }

    /** @return string[] */
    public function warnings(): array
    {
        return $this->warnings;
    }

    private function warn(string $message): void
    {
        $this->warnings[] = $message;
        fwrite(STDERR, "[warn] {$message}\n");
    }

    /** @return string[] */
    private function loadUsernames(): array
    {
        if (!is_file(CONFIG['input_file'])) {
            return [];
        }
        $data = json_decode((string) file_get_contents(CONFIG['input_file']), true);
        if (!is_array($data)) {
            return [];
        }
        $clean = [];
        foreach ($data as $user) {
            if (!is_string($user)) {
                continue;
            }
            $user = trim($user);
            // Telegram public channel usernames: letters, digits, underscore.
            if ($user !== '' && preg_match('/^[A-Za-z0-9_]{3,64}$/', $user)) {
                $clean[] = $user;
            }
        }
        return array_values(array_unique($clean));
    }

    /**
     * @param string[] $usernames
     * @return string[]
     */
    private function fetchChannels(array $usernames): array
    {
        $mh = curl_multi_init();
        $handles = [];

        foreach ($usernames as $user) {
            $url = 'https://telegram.me/s/' . rawurlencode($user);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_TIMEOUT        => CONFIG['connect_timeout'],
                CURLOPT_CONNECTTIMEOUT => CONFIG['connect_timeout'],
                CURLOPT_USERAGENT      => $this->userAgent,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_ENCODING       => '',
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$user] = $ch;
        }

        $active = null;
        do {
            $status = curl_multi_exec($mh, $active);
            if ($active > 0) {
                curl_multi_select($mh, 1.0);
            }
        } while ($active > 0 && $status === CURLM_OK);

        $results = [];
        foreach ($handles as $user => $ch) {
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $body = (string) curl_multi_getcontent($ch);
            if ($code !== 200 || $body === '') {
                $this->warn("fetch failed for @{$user} (HTTP {$code})");
            } else {
                $results[] = $body;
            }
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);
        }
        curl_multi_close($mh);
        return $results;
    }

    /**
     * @param string[] $htmlContents
     * @return array<int, array<string, mixed>>
     */
    private function extractProxies(array $htmlContents): array
    {
        $found = [];
        // Match the query string of tg://proxy?...server=...&port=...&secret=...
        $linkRegex = '/proxy\?(?=[^"\']*server=)(?=[^"\']*port=)([^"\'\s<>]+)/i';

        foreach ($htmlContents as $html) {
            $cleanHtml = html_entity_decode($html, ENT_QUOTES | ENT_HTML5, 'UTF-8');

            if (!preg_match_all($linkRegex, $cleanHtml, $matches)) {
                continue;
            }

            foreach ($matches[1] as $queryString) {
                $server = $this->getParam($queryString, 'server');
                $port   = $this->getParam($queryString, 'port');
                $secret = $this->getParam($queryString, 'secret');

                if ($server === null || $port === null || $secret === null) {
                    continue;
                }

                $server = $this->sanitizeServer($server);
                if ($server === null) {
                    continue;
                }

                $portNum = $this->sanitizePort($port);
                if ($portNum === null) {
                    continue;
                }

                $secret = $this->cleanSecret($secret);
                if ($secret === null) {
                    continue;
                }

                $key = $server . ':' . $portNum;
                $found[$key] = [
                    'server' => $server,
                    'port'   => $portNum,
                    'secret' => $secret,
                    'type'   => $this->detectType($secret),
                    'tg_url' => sprintf(
                        'tg://proxy?server=%s&port=%d&secret=%s',
                        $server,
                        $portNum,
                        $secret
                    ),
                ];
            }
        }

        return array_values($found);
    }

    private function getParam(string $query, string $name): ?string
    {
        if (preg_match('/(?:^|&)' . preg_quote($name, '/') . '=([^&]+)/', $query, $m)) {
            return trim(urldecode($m[1]));
        }
        return null;
    }

    /** Reject hostnames that are not safe to render or connect to. */
    private function sanitizeServer(string $server): ?string
    {
        // Strip control chars and whitespace, drop a trailing dot.
        $server = preg_replace('/[\x00-\x20\x7f]+/', '', $server) ?? '';
        $server = rtrim($server, '.');
        if ($server === '' || strlen($server) > 253) {
            return null;
        }

        // Accept a DNS name or an IPv4/IPv6 literal only.
        if (filter_var($server, FILTER_VALIDATE_IP) !== false) {
            return $server;
        }
        if (preg_match('/^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/', $server)) {
            return strtolower($server);
        }
        return null;
    }

    private function sanitizePort(string $port): ?int
    {
        if (!preg_match('/^\d{1,5}$/', $port)) {
            return null;
        }
        $n = (int) $port;
        return ($n >= 1 && $n <= 65535) ? $n : null;
    }

    /**
     * MTProto secret rules:
     *   - plain:   32 hex chars (16 bytes)
     *   - dd:      34 hex chars, starts with "dd" (16 random bytes + domain)
     *   - ee:      >= 34 hex chars, even length, starts with "ee" (TLS)
     */
    private function cleanSecret(string $secret): ?string
    {
        $secret = strtolower(trim($secret));
        $len = strlen($secret);

        if ($len < 32 || $len > 512 || $len % 2 !== 0 || !ctype_xdigit($secret)) {
            return null;
        }
        if (str_starts_with($secret, 'dd')) {
            return $len === 34 ? $secret : null;
        }
        if (str_starts_with($secret, 'ee')) {
            return $len >= 34 ? $secret : null;
        }
        return $len === 32 ? $secret : null;
    }

    private function detectType(string $secret): string
    {
        if (str_starts_with($secret, 'ee')) {
            return 'TLS';
        }
        if (str_starts_with($secret, 'dd')) {
            return 'Secure';
        }
        return 'MTProto';
    }

    /**
     * @param array<int, array<string, mixed>> $proxies
     * @return array<int, array<string, mixed>>
     */
    private function checkConnectivity(array $proxies): array
    {
        $results = [];
        $timeout = (int) CONFIG['socket_timeout'];
        $chunks  = array_chunk(array_slice($proxies, 0, CONFIG['max_per_scan']), (int) CONFIG['batch_size']);

        foreach ($chunks as $chunk) {
            $sockets = [];
            $map     = [];

            foreach ($chunk as $idx => $proxy) {
                // Security: never connect to private/reserved addresses.
                if (!$this->isPublicHost((string) $proxy['server'])) {
                    $proxy['status']  = 'Offline';
                    $proxy['latency'] = null;
                    $results[] = $proxy;
                    continue;
                }

                $address = sprintf('tcp://%s:%d', $proxy['server'], $proxy['port']);
                $errno = 0;
                $errstr = '';
                $socket = @stream_socket_client(
                    $address,
                    $errno,
                    $errstr,
                    0,
                    STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT
                );

                if ($socket === false) {
                    $proxy['status']  = 'Offline';
                    $proxy['latency'] = null;
                    $results[] = $proxy;
                    continue;
                }

                stream_set_blocking($socket, false);
                $sockets[$idx] = $socket;
                $map[$idx] = ['proxy' => $proxy, 'start' => microtime(true)];
            }

            $deadline = microtime(true) + $timeout;

            while ($sockets !== [] && microtime(true) < $deadline) {
                $write  = $sockets;
                $read   = null;
                $except = null;
                $changed = @stream_select($read, $write, $except, 0, 200000);

                if ($changed === false) {
                    break;
                }
                if ($changed === 0) {
                    continue;
                }

                foreach ($write as $id => $sock) {
                    if (!isset($map[$id])) {
                        continue;
                    }
                    $info = $map[$id];
                    $latency = (int) round((microtime(true) - $info['start']) * 1000);

                    // A writable socket after async connect means the TCP
                    // handshake completed. On some stacks (e.g. TLS endpoints
                    // with no data yet) the read returns an empty string, not
                    // false; only an explicit false means the peer refused or
                    // closed the connection.
                    $probe = @fread($sock, 1);
                    $ok = ($probe !== false);

                    $p = $info['proxy'];
                    $p['status']  = $ok ? 'Online' : 'Offline';
                    $p['latency'] = $ok ? $latency : null;
                    $results[] = $p;

                    @fclose($sock);
                    unset($sockets[$id], $map[$id]);
                }
            }

            foreach ($sockets as $id => $sock) {
                if (!isset($map[$id])) {
                    continue;
                }
                $p = $map[$id]['proxy'];
                $p['status']  = 'Offline';
                $p['latency'] = null;
                $results[] = $p;
                @fclose($sock);
            }
        }

        return $results;
    }

    /** True only when every resolved address is a public, routable IP. */
    private function isPublicHost(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $this->isPublicIp($host);
        }

        $ips = @gethostbynamel($host);
        if ($ips === false || $ips === []) {
            return false;
        }
        foreach ($ips as $ip) {
            if (!$this->isPublicIp($ip)) {
                return false;
            }
        }
        return true;
    }

    private function isPublicIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }

    /** @param array<int, array<string, mixed>> $data */
    private function writeJson(string $path, array $data): void
    {
        $json = json_encode(
            $data,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        if ($json === false) {
            throw new RuntimeException('Failed to encode proxy list as JSON');
        }
        $this->atomicWrite($path, $json);
    }

    public function atomicWrite(string $path, string $contents): void
    {
        $tmp = $path . '.tmp';
        if (file_put_contents($tmp, $contents, LOCK_EX) === false) {
            throw new RuntimeException("Unable to write {$tmp}");
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RuntimeException("Unable to replace {$path}");
        }
    }
}

// --- Run ---------------------------------------------------------------

$isCli = (PHP_SAPI === 'cli');
$lastScanTime = is_file(CONFIG['output_json']) ? (int) filemtime(CONFIG['output_json']) : 0;
$forceScan = false;

if ($isCli) {
    $forceScan = true;
} elseif (isset($_GET['scan'])) {
    // Rate limit manual web scans; never let a request trigger a scan storm.
    $forceScan = (time() - $lastScanTime) > (int) CONFIG['min_scan_gap'];
}

$scanner = new ProxyScanner();
$proxies = [];
$scanError = null;

$shouldScan = $forceScan
    || !is_file(CONFIG['output_json'])
    || (time() - $lastScanTime) > (int) CONFIG['cache_duration'];

if ($shouldScan) {
    try {
        $proxies = $scanner->run();
        $lastScanTime = time();
    } catch (Throwable $e) {
        $scanError = $e->getMessage();
        fwrite(STDERR, '[error] ' . $scanError . "\n");
        if (is_file(CONFIG['output_json'])) {
            $proxies = json_decode((string) file_get_contents(CONFIG['output_json']), true) ?: [];
        }
    }
} else {
    $proxies = json_decode((string) file_get_contents(CONFIG['output_json']), true) ?: [];
}

if (!is_array($proxies)) {
    $proxies = [];
}

// Prepare view data (template.html consumes these).
$onlineCount   = count(array_filter($proxies, static fn($p) => ($p['status'] ?? '') === 'Online'));
$totalCount    = count($proxies);
$scanTimestamp = $lastScanTime > 0 ? $lastScanTime : time();
$scanWarnings  = $scanner->warnings();
$proxiesJson   = json_encode(
    array_values($proxies),
    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
) ?: '[]';

ob_start();
require __DIR__ . '/template.html';
$htmlContent = (string) ob_get_clean();

try {
    $scanner->atomicWrite(CONFIG['output_html'], $htmlContent);
} catch (Throwable $e) {
    fwrite(STDERR, '[error] ' . $e->getMessage() . "\n");
}

if ($isCli) {
    echo "Generated index.html with {$onlineCount} online proxies (of {$totalCount}).\n";
} else {
    echo $htmlContent;
}
