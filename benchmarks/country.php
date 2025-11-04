<?php

ini_set('memory_limit', '1G');

/**
 * Load DBIP Country Lite CSV.GZ into a sorted flat cache.
 *
 * @param string $filename Path to .csv.gz file
 * @param bool $truncate Reset cache before load
 * @return void
 */
function load_country_cache_from_gz($filename, $record_size) {
	global $country_cache;

	if (($fp = gzopen($filename, 'r')) !== false) {
		while (($line = gzgets($fp)) !== false) {
$line = trim($line);
$ip_from_str = strtok($line, ',');
$ip_to_str = strtok(',');
$country = strtok(',');

// skip incomplete lines
if ($ip_from_str === false || $ip_to_str === false || $country === false) continue;

			$ip_from = @inet_pton($ip_from_str);
			$ip_to = @inet_pton($ip_to_str);

			if ($ip_from && $ip_to) {
			$len = strlen($ip_from);

			// Determine record size from first row
			if ($len !== $record_size) {
				continue;
			}

				$country_cache[] = [
					'ip_from' => $ip_from,
					'ip_to' => $ip_to,
					'country' => $country
				];
			}
		}
		gzclose($fp);
	}

	//~ // Sort by IP version then ip_to
	//~ usort($country_cache, function ($a, $b) {
		//~ $lenCmp = strlen($a['ip_to']) <=> strlen($b['ip_to']);
		//~ if ($lenCmp !== 0) return $lenCmp;
		//~ return strcmp($a['ip_to'], $b['ip_to']);
	//~ });
}


/**
 * Binary search the DBIP cache for a packed IP.
 *
 * @param string $ip_packed Packed binary IP (inet_pton result)
 * @return string Country code or '' if not found
 */
function get_country($ip_packed) {
	global $country_cache;

	$low = 0;
	$high = count($country_cache) - 1;

	while ($low <= $high) {
		$mid = ($low + $high) >> 1;
		$entry = $country_cache[$mid];

		if ($ip_packed > $entry['ip_to']) {
			$low = $mid + 1;
		} elseif ($ip_packed < $entry['ip_from']) {
			$high = $mid - 1;
		} else {
			return $entry['country']; // match
		}
	}

	return '';
}

global $country_cache_bin;
$country_cache_bin = '';

/**
 * Load DBIP .csv.gz into a single binary blob.
 *
 * @param string $filename Path to .csv.gz
 * @param int $record_size Expected record size
 */
function load_country_cache_bin($filename, $record_size) {
	global $country_cache_bin;

	if (($fp = gzopen($filename, 'r')) !== false) {
		while (($line = gzgets($fp)) !== false) {
			if (substr_count($line, ',') !== 2) {
				continue;
			}

			$ip_from_str = strtok($line, ',');
			$ip_to_str = strtok(',');
			$country = strtok(',');

			$ip_from = @inet_pton($ip_from_str);
			$ip_to = @inet_pton($ip_to_str);

			if (!$ip_from || !$ip_to) {
				continue;
			}

			$len = strlen($ip_from);

			if ($len !== $record_size) {
				continue;
			}

			$country_cache_bin .= $ip_from . $ip_to . substr($country, 0, 2);
		}
		gzclose($fp);
	}
}

/**
 * Binary search in the packed blob.
 *
 * @param string $ip_packed (inet_pton result)
 * @return string Country code or ''
 */
function get_country_bin($ip_packed) {
	global $country_cache_bin;

	$len = strlen($ip_packed);
	$record_size = $len * 2 + 2;
	$low = 0;
	$high = (int)(strlen($country_cache_bin) / $record_size) - 1;

	while ($low <= $high) {
		$mid = ($low + $high) >> 1;
		$offset = $mid * $record_size;

		if (substr_compare($country_cache_bin, $ip_packed, $offset + $len, $len) < 0) {
			// The IP we’re searching for is above this range
			$low = $mid + 1;
		} elseif (substr_compare($country_cache_bin, $ip_packed, $offset, $len) > 0) {
			// The IP we’re searching for is below this range
			$high = $mid - 1; 
		} else {
			// The IP lies within the current range
			return substr($country_cache_bin, $offset + $len * 2, 2);
		}
	}
	return '';
}

function assertSameOrder() {
	global $country_cache, $country_cache_bin;

	$count_array = count($country_cache);

	if ($count_array > 0) {
		$len = strlen($country_cache[0]['ip_from']);
	}

	$record_size = $len * 2 + 2;
	$count_bin = (int)(strlen($country_cache_bin) / $record_size);

	if ($count_array !== $count_bin) {
		echo "❌ Record count mismatch: array=$count_array, bin=$count_bin\n";
		return false;
	}

	for ($i = 0, $j = 0; $i < $count_array; $i += $record_size, $j++) {
		$ip_from_b = substr($country_cache_bin, $i, $len);
		$ip_to_b = substr($country_cache_bin, $i + $len, $len);
		$cc_b = substr($country_cache_bin, $i + $len * 2, 2);

		$a = $country_cache[$j];
		if ($ip_from_b !== $a['ip_from'] || $ip_to_b !== $a['ip_to'] || $cc_b !== $a['country']) {
			echo "❌ Mismatch at index $i\n";
			echo " Array: " . inet_ntop($a['ip_from']) . " → " . inet_ntop($a['ip_to']) . " : {$a['country']}\n";
			echo " Binary: " . inet_ntop($ip_from_b) . " → " . inet_ntop($ip_to_b) . " : $cc_b\n";
			return false;
		}
	}

	echo "✅ Verified: country_cache and country_cache_bin have identical records and order.\n";
	return true;
}

// Initialize a fixed seed for reproducible random output
mt_srand(123456); // choose any integer seed

/**
 * Generate a deterministic pseudo-random IPv4 address.
 *
 * @return string IPv4 string (e.g., "203.0.113.42")
 */
function randomIPv4(): string {
	// mt_rand() now produces deterministic sequence thanks to mt_srand()
	return long2ip(mt_rand(0, 0xFFFFFFFF));
}

/**
 * Generate a deterministic pseudo-random IPv6 address.
 *
 * @return string IPv6 string (e.g., "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
 */
function randomIPv6(): string {
	static $seed = 987654321; // separate deterministic seed for IPv6
	$bytes = '';

	// Simple linear congruential generator (LCG) for reproducible bytes
	for ($i = 0; $i < 16; $i++) {
		$seed = ($seed * 1103515245 + 12345) & 0x7FFFFFFF;
		$bytes .= chr($seed & 0xFF);
	}

	$parts = str_split(bin2hex($bytes), 4);
	return implode(':', $parts);
}


// Test lots of random IPs
$n = 100000; // adjust for stress test
$ipv6_test = 0; // toggle IPv6

memory_reset_peak_usage();
$start = microtime(true);
load_country_cache_from_gz("dbip-country-lite-2025-10.csv.gz", $ipv6_test ? 16 : 4);
echo "Loaded in " . round(microtime(true)-$start, 3) . "s\n";
echo "Peak memory: " . round(memory_get_peak_usage(true)/1048576, 2) . " MB\n";

$ip = "8.8.8.8";
$packed = inet_pton($ip);
$country = get_country($packed);
echo "$ip → $country\n";

memory_reset_peak_usage();
$mem = memory_get_peak_usage();
$start = microtime(true);
load_country_cache_bin("dbip-country-lite-2025-10.csv.gz", $ipv6_test ? 16 : 4);
echo "Loaded in " . round(microtime(true)-$start, 3) . "s\n";
echo "Peak memory: " . round((memory_get_peak_usage() - $mem) / 1048576, 2) . " MB\n";

assertSameOrder();

$start = microtime(true);
$hits = 0;
for ($i = 0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	$cc = get_country($packed);
	if ($cc !== '') $hits++;
}
$elapsed = microtime(true) - $start;
echo "Looked up $n IPs in " . round($elapsed, 3) . "s (" .
	 round($n / $elapsed) . " lookups/sec, hits=$hits)\n";

$start = microtime(true);
$hits = 0;
for ($i = 0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	$cc = get_country_bin($packed);
	if ($cc !== '') $hits++;
}
$elapsed = microtime(true) - $start;
echo "Looked up $n IPs in " . round($elapsed, 3) . "s (" .
	 round($n / $elapsed) . " lookups/sec, hits=$hits)\n";

$start = microtime(true);
$hits = 0;
for ($i = 0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	if (get_country_bin($packed) === get_country($packed)) $hits++;
}
$elapsed = microtime(true) - $start;
echo "Checked for equal results for $n IPs in " . round($elapsed, 3) . "s (" .
	 round($n / $elapsed) . " lookups/sec, hits=$hits)\n";

/**
 * Build jump table for packed IP ranges.
 *
 * Each slot points to the first record whose ip_to >= prefix boundary.
 *
 * For IPv4 → 256 entries (1 per /8)
 * For IPv6 → 65536 entries (1 per /16)
 *
 * @param string $country_cache_bin Binary blob (packed ranges)
 * @param int $len IP length (4 or 16)
 * @return array<int,int> Jump table (prefix => record index)
 */
function buildJumpTable($country_cache_bin, $len) {
	global $ord_cache;

	$record_size = $len * 2 + 2;
	$record_count = (int)(strlen($country_cache_bin) / $record_size);

	$table_size = $len === 4 ? 256 : 65536;
	$jump_table = array_fill(0, $table_size, $record_count); // default to end

	$prefix = 0;
	for ($i = 0, $j = 0; $i < $record_count; $i++, $j += $record_size) {
		// Extract prefix index
		if ($len === 4) {
			$prefix_val = $ord_cache[$country_cache_bin[$j + $len]];
		} else {
			$prefix_val = ($ord_cache[$country_cache_bin[$j + $len]] << 8) | $ord_cache[$country_cache_bin[$j + $len + 1]];
		}

		// Fill all slots up to this prefix
		while ($prefix <= $prefix_val && $prefix < $table_size) {
			$jump_table[$prefix] = $i;
			$prefix++;
		}
	}

	return $jump_table;
}

/**
 * Binary search packed IP ranges using jump table.
 *
 * @param string $ip_packed inet_pton result
 * @param array $jump_table Jump table for that IP family
 * @return string 2-char country code or ''
 */
function get_country_bin_jump(string $ip_packed, array $jump_table): string {
	global $country_cache_bin, $ord_cache;

	$len = strlen($ip_packed);
	$record_size = $len * 2 + 2;
	$record_count = (int)(strlen($country_cache_bin) / $record_size);

	// Compute prefix index
	$prefix = ($len === 4)
		? $ord_cache[$ip_packed[0]]
		: (($ord_cache[$ip_packed[0]] << 8) | $ord_cache[$ip_packed[1]]);

	// Determine search window
	$low = $jump_table[$prefix];
	$high = $jump_table[$prefix + 1] ?? $record_count - 1;

	while ($low <= $high) {
		$mid = ($low + $high) >> 1;
		$offset = $mid * $record_size;

		if (substr_compare($country_cache_bin, $ip_packed, $offset + $len, $len) < 0) {
			// The IP we’re searching for is above this range
			$low = $mid + 1;
		} elseif (substr_compare($country_cache_bin, $ip_packed, $offset, $len) > 0) {
			// The IP we’re searching for is below this range
			$high = $mid - 1; 
		} else {
			// The IP lies within the current range
			return substr($country_cache_bin, $offset + $len * 2, 2);
		}
	}

	return '';
}

// Use the same ord cache
global $ord_cache;

$ord_cache = range("\0", "\xFF");
$ord_cache = array_flip($ord_cache);

memory_reset_peak_usage();
$mem = memory_get_peak_usage();
$start = microtime(true);
$jump_table = buildJumpTable($country_cache_bin, $ipv6_test ? 16 : 4);
echo "Loaded in " . round(microtime(true)-$start, 3) . "s\n";
echo "Peak memory: " . round((memory_get_peak_usage() - $mem) / 1024, 2) . " KB\n";

$ip = "111.40.184.208";
$packed = inet_pton($ip);
$country = get_country_bin_jump($packed, $jump_table);
echo "$ip → $country\n";

$start = microtime(true);
$hits = 0;
for ($i = 0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	$cc = get_country_bin_jump($packed, $jump_table);
	if ($cc !== '') $hits++;
}
$elapsed = microtime(true) - $start;
echo "Looked up $n IPs in " . round($elapsed, 3) . "s (" .
	 round($n / $elapsed) . " lookups/sec, hits=$hits)\n";

$start = microtime(true);
$hits = 0;
for ($i = 0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	if (get_country_bin_jump($packed, $jump_table) === get_country($packed)) $hits++;
}
$elapsed = microtime(true) - $start;
echo "Checked for equal results for $n IPs in " . round($elapsed, 3) . "s (" .
	 round($n / $elapsed) . " lookups/sec, hits=$hits)\n";


for ($i = 0,$e=0; $i < $n; $i++) {
	$ip = $ipv6_test ? randomIPv6() : randomIPv4();
	$packed = inet_pton($ip);
	$cc1 = get_country_bin_jump($packed, $jump_table);
	$cc2 = get_country($packed);
	if ($cc1 !== $cc2) {
		echo "Mismatch at $ip → jump=$cc1, normal=$cc2\n";
		if(++$e===9 )
		break;
	}
}
