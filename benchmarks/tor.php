<?php
ini_set('memory_limit', '1G');

function build_regex($strings, $delim = null, $returnArray = false)
{
	global $smcFunc;
	static $regexes = array();

	// If it's not an array, there's not much to do. ;)
	if (!is_array($strings))
		return preg_quote(@strval($strings), $delim);

	$regex_key = md5(json_encode(array($strings, $delim, $returnArray)));

	if (isset($regexes[$regex_key]))
		return $regexes[$regex_key];

	// The mb_* functions are faster than the $smcFunc ones, but may not be available
	if (function_exists('mb_internal_encoding') && function_exists('mb_detect_encoding') && function_exists('mb_strlen') && function_exists('mb_substr'))
	{
		if (($string_encoding = mb_detect_encoding(implode(' ', $strings))) !== false)
		{
			$current_encoding = mb_internal_encoding();
			mb_internal_encoding($string_encoding);
		}

		$strlen = 'mb_strlen';
		$substr = 'mb_substr';
	}
	else
	{
		$strlen = $smcFunc['strlen'];
		$substr = $smcFunc['substr'];
	}

	// This recursive function creates the index array from the strings
	$add_string_to_index = function($string, $index) use (&$strlen, &$substr, &$add_string_to_index)
	{
		static $depth = 0;
		$depth++;

		$first = (string) @$substr($string, 0, 1);

		// No first character? That's no good.
		if ($first === '')
		{
			// A nested array? Really? Ugh. Fine.
			if (is_array($string) && $depth < 20)
			{
				foreach ($string as $str)
					$index = $add_string_to_index($str, $index);
			}

			$depth--;
			return $index;
		}

		if (empty($index[$first]))
			$index[$first] = array();

		if ($strlen($string) > 1)
		{
			// Sanity check on recursion
			if ($depth > 99)
				$index[$first][$substr($string, 1)] = '';

			else
				$index[$first] = $add_string_to_index($substr($string, 1), $index[$first]);
		}
		else
			$index[$first][''] = '';

		$depth--;
		return $index;
	};

	// This recursive function turns the index array into a regular expression
	$index_to_regex = function(&$index, $delim) use (&$strlen, &$index_to_regex)
	{
		static $depth = 0;
		$depth++;

		// Absolute max length for a regex is 32768, but we might need wiggle room
		$max_length = 30000;

		$regex = array();
		$length = 0;

		foreach ($index as $key => $value)
		{
			$key_regex = preg_quote($key, $delim);
			$new_key = $key;

			if (empty($value))
				$sub_regex = '';
			else
			{
				$sub_regex = $index_to_regex($value, $delim);

				if (count(array_keys($value)) == 1)
				{
					$new_key_array = explode('(?' . '>', $sub_regex);
					$new_key .= $new_key_array[0];
				}
				else
					$sub_regex = '(?' . '>' . $sub_regex . ')';
			}

			if ($depth > 1)
				$regex[$new_key] = $key_regex . $sub_regex;
			else
			{
				if (($length += strlen($key_regex . $sub_regex) + 1) < $max_length || empty($regex))
				{
					$regex[$new_key] = $key_regex . $sub_regex;
					unset($index[$key]);
				}
				else
					break;
			}
		}

		// Sort by key length and then alphabetically
		uksort(
			$regex,
			function($k1, $k2) use (&$strlen)
			{
				$l1 = $strlen($k1);
				$l2 = $strlen($k2);

				if ($l1 == $l2)
					return strcmp($k1, $k2) > 0 ? 1 : -1;
				else
					return $l1 > $l2 ? -1 : 1;
			}
		);

		$depth--;
		return implode('|', $regex);
	};

	// Now that the functions are defined, let's do this thing
	$index = array();
	$regex = '';

	foreach ($strings as $string)
		$index = $add_string_to_index($string, $index);

	if ($returnArray === true)
	{
		$regex = array();
		while (!empty($index))
			$regex[] = '(?' . '>' . $index_to_regex($index, $delim) . ')';
	}
	else
		$regex = '(?' . '>' . $index_to_regex($index, $delim) . ')';

	// Restore PHP's internal character encoding to whatever it was originally
	if (!empty($current_encoding))
		mb_internal_encoding($current_encoding);

	$regexes[$regex_key] = $regex;
	return $regex;
}

/**
 * Load Tor bulk exit list (IPv4 addresses) from a URL or local path.
 *
 * @param string $source URL (https://...) or local filename
 * @return array Sorted list of IPv4 dotted strings
 * @throws RuntimeException on fetch/read failure
 */
function loadTorExitList(string $source = 'https://check.torproject.org/torbulkexitlist'): array {
	$raw = @file_get_contents($source);
	if ($raw === false) {
		throw new RuntimeException("Failed to fetch or read Tor exit list from: $source");
	}

	$ips = [];
	foreach (explode("\n", $raw) as $line) {
		$line = trim($line);
		if ($line === '') continue;

		// keep only IPv4 addresses (bulk list is generally IPv4)
		if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			$ips[] = $line;
		}
	}

	// Deduplicate and sort (string sort is fine for dotted IPv4)
	$ips = array_values(array_unique($ips));
	sort($ips, SORT_STRING);
	return $ips;
}

/**
 * Build a packed binary blob of IPv4 addresses (4 bytes per record).
 *
 * @param array $ipv4List Sorted list of dotted IPv4 strings
 * @return string Binary blob where each record is inet_pton(ip) (4 bytes)
 */
function buildPackedBlob(array $ipv4List): string {
	$packedList = [];

	foreach ($ipv4List as $ip) {
		$packed = @inet_pton($ip);
		if ($packed === false || strlen($packed) !== 4) continue;

		$packedList[] = $packed;  // 4 bytes
	}

	sort($packedList, SORT_STRING); // string sort on binary is correct

	// Now build blob from *sorted packed* values
	$blob = implode('', $packedList);

	return $blob;
}

/**
 * Build a /8 jump table for a packed IPv4 blob.
 *
 * Jump table layout:
 *   - 256 entries for prefix 0..255
 *   - plus a sentinel at index 256 pointing to recordCount
 *
 * Each entry = index (int) of the first record whose first-octet >= prefix.
 *
 * @param string $packedBlob Packed IPv4 blob (4 bytes per record)
 * @return array<int,int> Jump table (size 257)
 */
function buildJumpTable(string $packedBlob): array {
	$recordSize = 4;
	$recordCount = (int)(strlen($packedBlob) / $recordSize);
	$tableSize = 256;
	$jump = array_fill(0, $tableSize, $recordCount - 1); // default sentinel = end

	// Walk records and record the first occurrence of each /8 prefix
	$currentPrefix = 0;
	for ($i = 0; $i < $recordCount; $i++) {
		$offset = $i * $recordSize;
		$firstOctet = ord($packedBlob[$offset]); // 0..255

		// Fill any missing prefixes up to this firstOctet with current index
		while ($currentPrefix <= $firstOctet && $currentPrefix <= 255) {
			$jump[$currentPrefix] = $i;
			$currentPrefix++;
		}

		if ($currentPrefix > 255) break;
	}

	// Any remaining prefixes not seen should point to recordCount (no entries)
	while ($currentPrefix <= 255) {
		$jump[$currentPrefix] = $recordCount;
		$currentPrefix++;
	}

	return $jump;
}

/**
 * Binary-search exact IPv4 match in a sorted array of dotted IPs.
 *
 * @param array $sortedIps Sorted list of dotted IPv4 strings
 * @param string $ip IPv4 dotted string to test ("x.x.x.x")
 * @return bool True if found (Tor exit), false otherwise
 */
function isTorExitIpArray(array $sortedIps, string $ip): bool {
	$low = 0;
	$high = count($sortedIps) - 1;
	while ($low <= $high) {
		$mid = ($low + $high) >> 1;
		$cmp = strcmp($sortedIps[$mid], $ip);
		if ($cmp === 0) return true;
		if ($cmp < 0) $low = $mid + 1;
		else $high = $mid - 1;
	}
	return false;
}

/**
 * Binary-search exact IPv4 match in the packed blob using jump table.
 *
 * @param string $packedBlob Packed IPv4 blob (4 bytes per record)
 * @param array $jumpTable Jump table from buildJumpTable()
 * @param string $ipPacked inet_pton($ip) (4 bytes)
 * @return bool True if found, false otherwise
 */
function isTorExitIpBinary(string $packedBlob, array $jumpTable, string $ipPacked): bool {
	$len = strlen($ipPacked);
	if ($len !== 4) return false; // only IPv4 supported here

	$recordSize = 4;
	$recordCount = (int)(strlen($packedBlob) / $recordSize);
	if ($recordCount === 0) return false;

	$prefix = ord($ipPacked[0]); // 0..255
	$low = $jumpTable[$prefix] ?? 0;
	$high = $jumpTable[$prefix + 1] ?? $recordCount - 1;

	while ($low <= $high) {
		$mid = ($low + $high) >> 1;
		$offset = $mid * $recordSize;

		// Compare the mid-record to the needle
		$cmpLow = substr_compare($packedBlob, $ipPacked, $offset, $len);
		if ($cmpLow === 0) {
			return true;
		} elseif ($cmpLow < 0) {
			// mid record < ip -> search above
			$low = $mid + 1;
		} else {
			// mid record > ip -> search below
			$high = $mid - 1;
		}
	}
	return false;
}

/**
 * Helper: convert packedIpv4 (4 bytes) to dotted string.
 *
 * @param string $packed
 * @return string
 */
function packedToDotted(string $packed): string {
	return inet_ntop($packed);
}

/**
 * Generate a deterministic pseudo-random IPv4 address (dotted).
 *
 * @return string IPv4 dotted string
 */
function randomIPv4(): string {
	// Use mt_rand for determinism when mt_srand() is set externally (your harness does this)
	return long2ip(mt_rand(0, 0xFFFFFFFF));
}

/**
 * Generate a deterministic pseudo-random IPv6 address.
 *
 * (Kept for compatibility with your harness; Tor list is IPv4-only.)
 *
 * @return string IPv6 string
 */
function randomIPv6(): string {
	static $seed = 987654321;
	$bytes = '';
	for ($i = 0; $i < 16; $i++) {
		$seed = ($seed * 1103515245 + 12345) & 0x7FFFFFFF;
		$bytes .= chr($seed & 0xFF);
	}
	$parts = str_split(bin2hex($bytes), 4);
	return implode(':', $parts);
}

/* -------------------------
   Main harness (benchmarks)
   ------------------------- */

// deterministic seed (keeps your harness reproducible)
mt_srand(123456);

$n = 100000;      // number of random lookups for benchmarks
$ipv6Test = false; // toggle IPv6 testing (Tor list is IPv4-only)

try {
	// load (URL or local file)
	$source = 'https://check.torproject.org/torbulkexitlist';
	$source = 'torbulkexitlist';
	$start = microtime(true);
	$torList = loadTorExitList($source);
	$loadElapsed = microtime(true) - $start;
	echo "Loaded Tor exit list: " . count($torList) . " IPv4 addresses in " . round($loadElapsed, 3) . "s\n";

	$start = microtime(true);
	sort($torList);
	$sortElapsed = microtime(true) - $start;
	echo "sorted Tor exit list: " . count($torList) . " IPv4 addresses in " . round($sortElapsed, 3) . "s\n";

	// build packed blob and jump table
	$start = microtime(true);
	$packedBlob = buildPackedBlob($torList);
	$jumpTable = buildJumpTable($packedBlob);
	$buildElapsed = microtime(true) - $start;
	$recordCount = (int)(strlen($packedBlob) / 4);
	echo "Built packed blob ($recordCount records) and jump table in " . round($buildElapsed, 3) . "s\n";

	// quick functional tests (a real IP and a likely-non exit)
	$sampleIp = $torList[0] ?? '1.2.3.4';
	echo "Sample known exit (first in list): $sampleIp\n";
	$packedSample = inet_pton($sampleIp);
	echo "isTorExitIpArray(sample)  -> " . (isTorExitIpArray($torList, $sampleIp) ? "YES" : "NO") . "\n";
	echo "isTorExitIpBinary(sample) -> " . (isTorExitIpBinary($packedBlob, $jumpTable, $packedSample) ? "YES" : "NO") . "\n";

	$testIp = '1.2.3.4'; // likely not an exit
	$packedTest = inet_pton($testIp);
	echo "$testIp -> array: " . (isTorExitIpArray($torList, $testIp) ? "YES" : "NO") . ", binary: " .
		(isTorExitIpBinary($packedBlob, $jumpTable, $packedTest) ? "YES" : "NO") . "\n";

	// Benchmark: array-based binary search
	$start = microtime(true);
	$regex = build_regex($torList);
	$elapsed = microtime(true) - $start;
	echo "Built regex in " . round($elapsed, 3) . "s\n";

	// Benchmark: array-based binary search
	$hits = 0;
	$elapsed = 0;
	for ($i = 0; $i < $n; $i++) {
		$ip = $i % 10 === 0 ? $torList[array_rand($torList)] : randomIPv4();
	$start = microtime(true);
		if (preg_match('/' . $regex . '/', $ip)) $hits++;
	$elapsed += microtime(true) - $start;
	}
	echo "Regex search: checked $n IPs in " . round($elapsed, 3) . "s (" . round($n / $elapsed) . " lookups/sec), hits=$hits\n";

	// Benchmark: array-based binary search
	$hits = 0;
	$elapsed = 0;
	for ($i = 0; $i < $n; $i++) {
		$ip = $i % 10 === 0 ? $torList[array_rand($torList)] : randomIPv4();
	$start = microtime(true);
		if (isTorExitIpArray($torList, $ip)) $hits++;
	$elapsed += microtime(true) - $start;
	}
	echo "Array search: checked $n IPs in " . round($elapsed, 3) . "s (" . round($n / $elapsed) . " lookups/sec), hits=$hits\n";

	// Benchmark: binary blob + jump table
	$hits = 0;
	$elapsed = 0;
	for ($i = 0; $i < $n; $i++) {
		$ip = $i % 10 === 0 ? $torList[array_rand($torList)] : randomIPv4();
		$packed = inet_pton($ip);
	$start = microtime(true);
		if (isTorExitIpBinary($packedBlob, $jumpTable, $packed)) $hits++;
	$elapsed += microtime(true) - $start;
	}
	echo "Binary blob search: checked $n IPs in " . round($elapsed, 3) . "s (" . round($n / $elapsed) . " lookups/sec), hits=$hits\n";

	// Sanity: compare equality for many randoms (binary vs array)
	$start = microtime(true);
	$agree = 0;
	for ($i = 0; $i < $n; $i++) {
		$ip = $i % 10 === 0 ? $torList[array_rand($torList)] : randomIPv4();
		$packed = inet_pton($ip);
		$a = isTorExitIpArray($torList, $ip);
		$b = isTorExitIpBinary($packedBlob, $jumpTable, $packed);
		if ($a === $b) $agree++;
		else {
			// show first few mismatches
			static $printed = 0;
			if ($printed < 10) {
				echo "Mismatch for $ip: array=" . ($a ? '1' : '0') . " binary=" . ($b ? '1' : '0') . "\n";
				$printed++;
			}
		}
	}
	$elapsed = microtime(true) - $start;
	echo "Verified equality for $n checks in " . round($elapsed, 3) . "s (agree=$agree/$n)\n";

} catch (Exception $e) {
	echo "Error: " . $e->getMessage() . "\n";
}
