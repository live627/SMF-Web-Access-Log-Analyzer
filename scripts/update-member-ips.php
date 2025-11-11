<?php
// SMF script to update all members with deterministic random IPs
// Requires SMF bootstrap (SSI) or direct DB credentials.

// --- CONFIG --------------------------------------------------------------
$useSSI = true; // set false if including Settings.php manually

if ($useSSI) {
	require_once(__DIR__ . '/SSI.php');
} else {
	require_once(__DIR__ . '/Settings.php');
	$db = mysqli_connect($db_server, $db_user, $db_passwd, $db_name);
}

// Initialize deterministic seeds
mt_srand(123456);

function randomIPv4(): string {
	return long2ip(mt_rand(0, 0xFFFFFFFF));
}

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

// Fetch all member IDs
$request = $smcFunc['db_query']('', 'SELECT id_member FROM {db_prefix}members');

$members = [];
while ($row = $smcFunc['db_fetch_assoc']($request)) {
	$members[] = (int) $row['id_member'];
}
$smcFunc['db_free_result']($request);

// Update each member
foreach ($members as $id) {
	$ipv4 = randomIPv4();
	$ipv6 = randomIPv6();

	$smcFunc['db_query']('', '
		UPDATE {db_prefix}members
		SET member_ip = {inet:ip4},
			member_ip2 = {inet:ip6}
		WHERE id_member = {int:id}',
		[
			'ip4' => $ipv4,
			'ip6' => $ipv6,
			'id'  => $id,
		]
	);
}

echo "Updated " . count($members) . " members with deterministic IP addresses.\n";
