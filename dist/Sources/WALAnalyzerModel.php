<?php
/**
 *	DB interaction for the Web Access Log Analyzer mod for SMF..
 *
 *	Copyright 2025 Shawn Bulen
 *
 *	The Web Access Log Analyzer is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This software is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this software.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

// If we are outside SMF throw an error.
if (!defined('SMF')) {
    die('Hacking attempt...');
}

/**
 * start_transaction
 *
 * @return null
 *
 */
function start_transaction() {
	global $smcFunc;

	$smcFunc['db_transaction']('begin');
}

/**
 * commit
 *
 * @return null
 *
 */
function commit() {
	global $smcFunc;

	$smcFunc['db_transaction']('commit');
}

/**
 * truncate_members
 *
 * @return null
 *
 */
function truncate_members() {
	global $smcFunc;

	$smcFunc['db_query']('', 'TRUNCATE {db_prefix}wala_members',
		array()
	);
	// Reflect status...
	update_status('member');
}

/**
 * truncate_web_access_log
 *
 * @return null
 *
 */
function truncate_web_access_log() {
	global $smcFunc;

	$smcFunc['db_query']('', 'TRUNCATE {db_prefix}wala_web_access_log',
		array()
	);
	// Reflect status...
	update_status('log');
}

/**
 * insert_dbip_asn
 *
 * @param array $inserts
 *
 * @return null
 *
 */
function insert_dbip_asn($inserts) {
	global $smcFunc, $modSettings;

	if (empty($inserts))
		return;

	// Temporarily disable query check...  Takes a MASSIVE amount of time on large inserts...
	$modSettings['disableQueryCheck'] = '1';
	$smcFunc['db_query']('', 'TRUNCATE {db_prefix}wala_asns');
	$chunk = [];

	while (($key = key($inserts)) !== null) {
		$value = current($inserts);
		$chunk[] = [$key, $value];
		next($inserts);

		// If we hit the chunk size or reached the end
		if (count($chunk) === 100 || key($inserts) === null) {
			$smcFunc['db_insert']('insert',
				'{db_prefix}wala_asns',
				array('asn' => 'string-10', 'asn_name' => 'string-255'),
				$chunk,
				array('asn'),
			);
			$chunk = []; // reset for next batch
		}
	}
}

/**
 * Insert web access log entries and log the execution time.
 *
 * @param array $inserts Array of rows to insert
 */
function insert_log($inserts) {
	global $smcFunc, $modSettings;

	if (empty($inserts))
		return;

	// Temporarily disable query check...  Takes a MASSIVE amount of time on large inserts...
	$modSettings['disableQueryCheck'] = '1';

	$smcFunc['db_insert']('insert',
		'{db_prefix}wala_web_access_log',
		array(
			'ip_packed' => 'inet',
			'client' => 'string-10',
			'requestor' => 'string-10',
			'raw_datetime' => 'string-32',
			'raw_tz' => 'string-6',
			'request' => 'string-255',
			'status' => 'int',
			'size' => 'int',
			'referrer' => 'string-255',
			'useragent' => 'string-255',
			'ip_disp' => 'string-42',
			'request_type' => 'string-15',
			'agent' => 'string-25',
			'browser_ver' => 'string-25',
			'datetime' => 'int',
		),
		$inserts,
		array('id_entry')
	);
	return;
	$affected_rows = $smcFunc['db_affected_rows']();

	// Now get warnings
	$request = $smcFunc['db_query']('', 'SHOW WARNINGS', array());
	$warnings = array();

	while ($row = $smcFunc['db_fetch_assoc']($request)) {
		$warnings[] = $row;
	}

	$smcFunc['db_free_result']($request);

	// Optional: log or display warnings
	foreach ($warnings as $w) {
		trigger_error("MySQL Warning: {$w['Level']} [{$w['Code']}] {$w['Message']}");
	}

	return $affected_rows;
}

/**
 * Efficiently insert multiple rows into a MySQL table using prepared statements.
 *
 * This function is optimized for bulk inserts from large datasets or generators.
 * It minimizes prepare overhead by creating at most two prepared statements:
 * one for full-size batches and one for any remaining partial batch.
 *
 * @param string      $method         One of 'insert', 'replace', or 'ignore'.
 * @param string      $table          Table name; may include {db_prefix}.
 * @param array       $columns        Column definitions in the form name => type.
 *                                   Supported base types: int, float, string, text,
 *                                   date, time, datetime, inet.
 *                                   Use "string-N" to limit VARCHAR input to N chars.
 * @param iterable    $data           Iterable rows to insert (array of arrays or generator).
 * @param array       $keys           Unused (kept for compatibility with SMF core).
 * @param mysqli|null $connection     Optional mysqli connection; defaults to $db_connection.
 * @param int         $rows_per_batch Number of rows per batch for prepared execution (default 100).
 */
function smf_db_insert_bactches($method, $table, $columns, $data, $keys = [], $connection = null, $rows_per_batch = 100)
{
	global $db_connection, $db_prefix;

	$conn = $connection ?? $db_connection;
	$method = strtolower($method);
	$table = str_replace('{db_prefix}', $db_prefix, $table);
	$query_title = $method === 'replace' ? 'REPLACE' : ($method === 'ignore' ? 'INSERT IGNORE' : 'INSERT');

	// Map SMF types to mysqli bind types
	$param_type_map = [
		'int' => 'i',
		'float' => 'd',
		'string' => 's',
		'text' => 's',
		'date' => 's',
		'time' => 's',
		'datetime' => 's',
		'inet' => 's',
	];
	$per_row_types = '';

	// Build column string and single-row placeholders
	$col_names = array_keys($columns);
	$col_string = '`' . implode('`,`', $col_names) . '`';
	$placeholders = [];

	foreach ($columns as $col => $type) {
		$param_type = strtok($type, '-');

		if (!isset($param_type_map[$param_type]))
			smf_db_error_backtrace('Invalid type for ' . $col . ': ' . $type, '', E_USER_ERROR, __FILE__, __LINE__);

		$max_len = strtok('-');
		$per_row_types .= $param_type_map[$param_type];

		if ($param_type === 'string' && $max_len) {
			$placeholders[] = "SUBSTRING(?, 1, $max_len)";
		} elseif ($type === 'inet') {
			$placeholders[] = 'INET6_ATON(?)';
		} else {
			$placeholders[] = '?';
		}
	}
	$row_placeholder = '(' . implode(', ', $placeholders) . ')';

	$sql = "$query_title INTO $table ($col_string) VALUES " .
		substr(str_repeat("$row_placeholder,", $rows_per_batch), 0, -1);
	$stmt = $conn->prepare($sql);
	if (!$stmt)
		smf_db_error_backtrace('Prepare failed: ' . $conn->error, '', E_USER_ERROR, __FILE__, __LINE__);

	$stmt_partial = null;
	$bind_types = str_repeat($per_row_types, $rows_per_batch);

	// === Stream directly ===
	$row_counter = 0;
	$param_index = 0;
	$bind_values = array_fill(0, $rows_per_batch * count($columns), '');
	$bound = false;

	foreach ($data as $row) {
		foreach ($row as $v)
			$bind_values[$param_index++] = $v;

		$row_counter++;

		if ($row_counter === $rows_per_batch) {
			if (!$bound) {
				$stmt->bind_param($bind_types, ...$bind_values);
				$bound = true;
			}

			if (!$stmt->execute())
				smf_db_error_backtrace('Execute failed: ' . $stmt->error, '', E_USER_ERROR, __FILE__, __LINE__);

			// Reset accumulators
			$row_counter = 0;
			$param_index = 0;
		}
	}

	$stmt->close();

	// === Final leftover rows ===
	if ($row_counter !== 0) {
		$sql = "$query_title INTO $table ($col_string) VALUES " .
			substr(str_repeat("$row_placeholder,", $row_counter), 0, -1);
		$stmt = $conn->prepare($sql);

		if (!$stmt)
			smf_db_error_backtrace('Prepare failed: ' . $conn->error, '', E_USER_ERROR, __FILE__, __LINE__);

		$bind_types = str_repeat($per_row_types, $row_counter);
		$stmt->bind_param($bind_types, ...array_slice($bind_values, 0, $row_counter * count($columns)));

		if (!$stmt->execute())
			smf_db_error_backtrace('Execute failed: ' . $stmt->error, '', E_USER_ERROR, __FILE__, __LINE__);

		$stmt->close();
	}
}

/**
 * count_smf_members
 *
 * @return int
 *
 */
function count_smf_members() {
	global $smcFunc;
	$rec_count = 0;

	$result = $smcFunc['db_query']('', 'SELECT COUNT(*) AS reccount FROM {db_prefix}members');
	$rec_count = (int) $smcFunc['db_fetch_assoc']($result)['reccount'];
	return $rec_count;
}

/**
 * count_web_access_log
 *
 * @return int
 *
 */
function count_web_access_log() {
	global $smcFunc;
	$rec_count = 0;

	$result = $smcFunc['db_query']('', 'SELECT COUNT(*) AS reccount FROM {db_prefix}wala_web_access_log');
	$rec_count = $smcFunc['db_fetch_assoc']($result)['reccount'];
	return $rec_count;
}

/**
 * get_smf_members - read a chunk of members from smf_members to load to reporting db
 *
 * @params int offset
 * @params int limit
 *
 * @return array
 *
 */
function get_smf_members($offset = 0, $limit = 50000) {
	global $smcFunc, $db_type;

	$result = $smcFunc['db_query']('', 'SELECT member_ip, id_member, real_name, is_activated , posts, total_time_logged_in, date_registered, last_login FROM {db_prefix}members ORDER BY id_member ASC LIMIT ' . $limit . ' OFFSET ' . $offset);

	// Under SMF, PG & MySQL behave differently with inet types.  MySQL reads binary, but wants a display upon insert.
	// PG always reads & writes display.
	// We need display, for this member load, so pg is ok.
	$all_rows = array();
	while ($row = $smcFunc['db_fetch_assoc']($result)) {
		if ($db_type == 'mysql') {
			$row['member_ip'] = inet_ntop($row['member_ip']);
		}
		$all_rows[] = $row;
	}
	return $all_rows;
}

/**
 * insert_members - load a chunk of members to reporting db
 *
 * @params array $inserts
 *
 * @return null
 *
 */
function insert_members(&$inserts) {
	global $smcFunc, $modSettings;

	if (empty($inserts))
		return;

	// Temporarily disable query check...  Takes a MASSIVE amount of time on large inserts...
	$modSettings['disableQueryCheck'] = '1';

	$smcFunc['db_insert']('insert',
		'{db_prefix}wala_members',
		array('ip_packed' => 'inet', 'id_member' => 'int', 'real_name' => 'string-255', 'is_activated' => 'int', 'posts' => 'int', 'total_time_logged_in' => 'int', 'date_registered' => 'int', 'last_login' => 'int'),
		$inserts,
		array('id_member'),
	);
}

/**
 * get_member_ips - load member IPs & names from reporting db
 *
 * @return array
 *
 */
function get_member_ips() {
	global $smcFunc, $db_type;

	if ($db_type == 'postgresql')
		$sql = 'SELECT ip_packed, real_name FROM {db_prefix}wala_members ORDER BY ip_packed ASC';
	else
		$sql = 'SELECT ip_packed, real_name FROM {db_prefix}wala_members ORDER BY LENGTH(ip_packed), ip_packed ASC';

	var_dump($sql);

	$start = microtime(true);

	$result = $smcFunc['db_query']('', $sql);

	$total = microtime(true) - $start;
	printf("Qeury took %.4f seconds\n", $total);

	// Under SMF, PG & MySQL behave differently with inet types.  MySQL reads binary, but wants a display upon insert.
	// PG always reads & writes display.
	// WALA uses binary on reads, so needs to xlate pg on reads here.
	$all_rows = array();
	while ($row = $smcFunc['db_fetch_assoc']($result)) {
		if ($db_type == 'postgresql') {
			$row['ip_packed'] = inet_pton($row['ip_packed']);
		}
		$all_rows[] = $row;
	}
	return $all_rows;
}

/**
 * load_asn_names - load unique asns & names
 *
 * @return null
 *
 */
function load_asn_names() {
	global $smcFunc, $modSettings;

	$smcFunc['db_query']('', 'TRUNCATE {db_prefix}wala_asns',
		array()
	);

	$result = $smcFunc['db_query']('', 'SELECT DISTINCT(asn), asn_name FROM {db_prefix}wala_dbip_asn ORDER BY asn');
	$inserts = $smcFunc['db_fetch_all']($result);

	// Temporarily disable query check...  Takes a MASSIVE amount of time on large inserts...
	$modSettings['disableQueryCheck'] = '1';

	$smcFunc['db_insert']('insert',
		'{db_prefix}wala_asns',
		array('asn' => 'string-10', 'asn_name' => 'string-255'),
		$inserts,
		array('asn'),
	);
}

/**
 * get_status - get all status info about uploads
 *
 * @return array
 *
 */
function get_status() {
	global $smcFunc;

	$result = $smcFunc['db_query']('', 'SELECT * FROM {db_prefix}wala_status');
	$all_rows = $smcFunc['db_fetch_all']($result);
	return $all_rows;
}

/**
 * update_status
 *
 * @params string file_type
 * @params string file_name
 * @params int datetime
 *
 * @return null
 *
 */
function update_status($file_type, $file_name = '', $last_proc_time = 0) {
	global $smcFunc;

	$smcFunc['db_insert']('replace',
		'{db_prefix}wala_status',
		array('file_type' => 'string-10', 'file_name' => 'string-255', 'last_proc_time' => 'int'),
		array(array($file_type, $file_name, $last_proc_time)),
		array('file_type'),
	);
}

/**
 * wala_report_request
 * Does some simple xlation of MySQL syntax to Postgresql
 *
 * @params string sql
 *
 * @return array
 *
 */
function wala_report_request($sql = '') {
	global $smcFunc, $db_type;

	if (empty($sql))
		return array();

	if ($db_type == 'postgresql')
		$sql = strtr($sql, array(
				'FROM_UNIXTIME' => 'TO_TIMESTAMP',
			)
		);

	$result = $smcFunc['db_query']('', $sql);
	$all_rows = $smcFunc['db_fetch_all']($result);
	return $all_rows;
}

/**
 * get_wala_members
 *
 * @params int offset
 * @params int limit
 *
 * @return array
 *
 */
function get_wala_members($offset, $limit) {
	global $smcFunc, $db_type;

	// pg properly sorts ip with ipv4 first, ipv6 next... mysql doesn't, and we don't want ipv6 & ipv4 all mixed together...
	if ($db_type == 'postgresql')
		$sql = 'SELECT ip_packed, id_member FROM {db_prefix}wala_members ORDER BY ip_packed, id_member LIMIT ' . $limit . ' OFFSET ' .$offset;
	else
		$sql = 'SELECT ip_packed, id_member FROM {db_prefix}wala_members ORDER BY LENGTH(ip_packed), ip_packed, id_member LIMIT ' . $limit . ' OFFSET ' .$offset;

	$result = $smcFunc['db_query']('', $sql);
	$all_rows = array();
	while ($row = $smcFunc['db_fetch_assoc']($result)) {
		if ($db_type == 'postgresql') {
			$row['ip_packed'] = inet_pton($row['ip_packed']);
		}
		$all_rows[] = $row;
	}
	return $all_rows;
}

/**
 * update_wala_members
 *
 * @params array $member_info
 *
 */
function update_wala_members($member_info) {
	global $smcFunc, $db_type;

	$sql = 'UPDATE {db_prefix}wala_members SET asn = \'' . $member_info['asn'] . '\', country = \'' . $member_info['country'] . '\' WHERE id_member = ' . $member_info['id_member'];
	$result = $smcFunc['db_query']('', $sql);
}

/**
 * get_web_access_log
 *
 * @params int offset
 * @params int limit
 *
 * @return array
 *
 */
function get_web_access_log($offset, $limit) {
	global $smcFunc, $db_type;

	$start = microtime(true);
	// pg properly sorts ip with ipv4 first, ipv6 next... mysql doesn't, and we don't want ipv6 & ipv4 all mixed together...
	if ($db_type == 'postgresql')
		$sql = 'SELECT ip_packed, id_entry FROM {db_prefix}wala_web_access_log ORDER BY ip_packed, id_entry LIMIT ' . $limit . ' OFFSET ' .$offset;
	else
		$sql = 'SELECT ip_packed, id_entry FROM {db_prefix}wala_web_access_log ORDER BY LENGTH(ip_packed), ip_packed, id_entry LIMIT ' . $limit . ' OFFSET ' .$offset;

	$result = $smcFunc['db_query']('', $sql);
	$output = array();
	while ($row = $smcFunc['db_fetch_assoc']($result)) {
		if ($db_type == 'postgresql') {
			$row['ip_packed'] = inet_pton($row['ip_packed']);
		}
		$output[] = $row;
	}

	return $output;
}

/**
 * Batch updates web access log entries in groups of 100, using string concatenation.
 *
 * @param array $entries Array of associative arrays with keys:
 *   - id_entry
 *   - asn
 *   - country
 *   - username
 */
function update_web_access_log2(array $entries) {
	global $smcFunc;

	if (empty($entries))
		return;

	$batch_size = 100;
	$count = 0;

	$sql_cases_asn = '';
	$sql_cases_country = '';
	$sql_cases_username = '';
	$sql_ids = '';

	foreach ($entries as $row) {
		$id = (int)$row['id_entry'];
		$asn = unpack('N', $row['asn'])[1];
		$country = $smcFunc['db_escape_string']($row['country']);
		$username = $smcFunc['db_escape_string']($row['username']);

		$sql_cases_asn .= " WHEN $id THEN '$asn'";
		$sql_cases_country .= " WHEN $id THEN '$country'";
		$sql_cases_username .= " WHEN $id THEN '$username'";
		$sql_ids .= $id . ',';

		$count++;

		// Every 100 entries, execute batch
		if ($count % $batch_size === 0) {
			$sql = '
				UPDATE {db_prefix}wala_web_access_log
				SET
					asn = CASE id_entry' . $sql_cases_asn . ' END,
					country = CASE id_entry' . $sql_cases_country . ' END,
					username = CASE id_entry' . $sql_cases_username . ' END
				WHERE id_entry IN (' . rtrim($sql_ids, ',') . ')';

			$smcFunc['db_query']('', $sql);

			// Reset for next batch
			$sql_cases_asn = '';
			$sql_cases_country = '';
			$sql_cases_username = '';
			$sql_ids = '';
		}
	}

	// Handle remainder
	if ($sql_ids !== '') {
		$sql = '
			UPDATE {db_prefix}wala_web_access_log
			SET
				asn = CASE id_entry' . $sql_cases_asn . ' END,
				country = CASE id_entry' . $sql_cases_country . ' END,
				username = CASE id_entry' . $sql_cases_username . ' END
			WHERE id_entry IN (' . rtrim($sql_ids, ',') . ')';

		$smcFunc['db_query']('', $sql);
	}
}

/**
 * Base class for web access log update errors.
 */
class WebAccessLogUpdateException extends Exception {
	public $context;

	public function __construct($message, array $context = [], $code = 0, Throwable $previous = null) {
		parent::__construct($message, $code, $previous);
		$this->context = $context;
	}

	public function __toString() {
		$str = __CLASS__ .': ' . ($this->code === 0 ? '' : '[' . $this->code . '] ') . $this->message;
		foreach ($this->context as $k => $ctx) {
			if (is_scalar($ctx)) {
				$str .= "\n\n" . $k . ': ' . $ctx;
			} elseif ($k === 'params') {
				$str .= "\n\n" . debugBindParams($ctx[0], $ctx[1]);
			} elseif ($k === 'sql') {
				$str .= "\n\n" . interpolateQuery($ctx[0], $ctx[1]);
			}
		}

		return $str;
	}
}

class WebAccessLogPrepareException extends WebAccessLogUpdateException {}
class WebAccessLogExecuteException extends WebAccessLogUpdateException {}

/**
 * Batch updates web access log entries in groups of 100 using string concatenation and reusable prepared statements.
 *
 * @param array $entries Array of associative arrays with keys:
 *   - id_entry
 *   - asn
 *   - country
 *   - username
 */
function update_web_access_log(array $entries) {
	global $db_connection, $db_prefix;

	if (empty($entries))
		return;

	$count = 0;
	$batch_size = 100;

	$params = array_fill(0, $batch_size * 7, null);
	$types = str_repeat('ii', $batch_size);
	$types .= str_repeat('is', $batch_size);
	$types .= str_repeat('is', $batch_size);
	$types .= str_repeat('i', $batch_size);

	$sql_cases = str_repeat(' WHEN ? THEN ?', $batch_size);
	$sql_ids = str_repeat('?,', $batch_size);

	$sql = '
		UPDATE ' .  $db_prefix . 'wala_web_access_log
		SET
			asn = CASE id_entry' . $sql_cases . ' END,
			country = CASE id_entry' . $sql_cases . ' END,
			username = CASE id_entry' . $sql_cases . ' END
		WHERE id_entry IN (' . rtrim($sql_ids, ',') . ')';
	$stmt_100 = $db_connection->prepare($sql);

	if (!$stmt_100) {
		throw new WebAccessLogPrepareException('Prepare failed for main batch', [
			'error' => $db_connection->error,
			'batch_size' => $batch_size,
			'sql' => $sql,
		]);
	}

	for ($i = 0, $n = count($entries); $i < $n; $i++) {
		$asn_index = $count * 2;
		$country_index = $count * 2 + $batch_size * 2;
		$username_index = $count * 2 + $batch_size * 4;
		$id_index = $count + $batch_size * 6;
		$count++;
		$id = (int)$entries[$i]['id_entry'];
		$asn = $entries[$i]['asn'];
		$country = $entries[$i]['country'];
		$username = $entries[$i]['username'];

		$params[$asn_index] = $id;
		$params[$asn_index + 1] = $asn;
		$params[$country_index] = $id;
		$params[$country_index + 1] = $country;
		$params[$username_index] = $id;
		$params[$username_index + 1] = $username;
		$params[$id_index] = $id;

		// When we reach a batch of 100 entries, execute
		if ($count === $batch_size) {
			$count = 0;
			if (!$stmt_100->bind_param($types, ...$params)) {
				throw new WebAccessLogExecuteException('bind_param failed', [
					'error' => $stmt_100->error,
					'batch_size' => $batch_size,
					'current_batch' => ($i + 1) % $batch_size,
					'current_iteration' => $i,
					'sql' => $sql,
					'params' => [$types, $params],
				]);
			}

			if (!$stmt_100->execute()) {
				throw new WebAccessLogExecuteException('Execute failed for main batch', [
					'error' => $stmt_100->error,
					'batch_size' => $batch_size,
					'current_batch' => ($i + 1) % $batch_size,
					'current_iteration' => $i,
					'sql' => [$sql, $params],
					'params' => [$types, $params],
				]);
			}
		}
	}

	// Handle remainder (last batch < 100)
	if ($count > 0) {
		$types_remainder = str_repeat('ii', $count);
		$types_remainder .= str_repeat('is', $count);
		$types_remainder .= str_repeat('is', $count);
		$types_remainder .= str_repeat('i', $count);

		$sql_cases_r = str_repeat(' WHEN ? THEN ?', $count);
		$sql_ids_r = rtrim(str_repeat('?,', $count), ',');

		$sql_last = '
			UPDATE ' .  $db_prefix . 'wala_web_access_log
			SET
				asn = CASE id_entry' . $sql_cases_r . ' END,
				country = CASE id_entry' . $sql_cases_r . ' END,
				username = CASE id_entry' . $sql_cases_r . ' END
			WHERE id_entry IN (' . $sql_ids_r . ')';

		$stmt_last = $db_connection->prepare($sql_last);

		$asn_block = array_slice($params, 0, $count * 2);
		$country_block = array_slice($params, $batch_size * 2, $count * 2);
		$username_block = array_slice($params, $batch_size * 4, $count * 2);
		$id_block = array_slice($params, $batch_size * 6, $count);

		$trimmed = array_merge($asn_block, $country_block, $username_block, $id_block);

		if (!$stmt_last->bind_param($types_remainder, ...$trimmed)) {
			throw new WebAccessLogExecuteException('bind_param failed', [
				'error' => $stmt_last->error,
				'batch_size' => $batch_size,
				'current_batch' => ($i + 1) % $batch_size,
				'current_iteration' => $i,
				'sql' => $sql_last,
				'params' => [$types_remainder, $trimmed],
			]);
		}

		if (!$stmt_last->execute()) {
			throw new WebAccessLogExecuteException('Execute failed for main batch', [
				'error' => $stmt_last->error,
				'batch_size' => $batch_size,
				'current_batch' => ($i + 1) % $batch_size,
				'current_iteration' => $i,
				'sql' => [$sql_last, $trimmed],
				'params' => [$types_remainder, $trimmed],
			]);
		}
		$stmt_last->close();
	}

	if ($stmt_100)
		$stmt_100->close();
}
/**
 * Batch insert/update (upsert) web access log entries using
 * INSERT ... ON DUPLICATE KEY UPDATE.
 *
 * @param array $entries Array of associative arrays:
 *   - id_entry
 *   - asn
 *   - country
 *   - username
 */
function upsert_web_access_log(array $entries) {
	global $db_connection, $db_prefix;

	if (empty($entries))
		return;

	$batch_size = 100;
	$batch = [];

	foreach ($entries as $entry) {
		$batch[] = $entry;
		if (count($batch) >= $batch_size) {
			executeUpsertBatch($db_connection, $db_prefix, $batch);
			$batch = [];
		}
	}

	// handle remainder
	if (!empty($batch)) {
		executeUpsertBatch($db_connection, $db_prefix, $batch);
	}
}

/**
 * Executes a single upsert batch.
 */
function executeUpsertBatch(mysqli $db, string $prefix, array $batch) {
	$placeholders = [];
	$params = [];
	$types = '';

	foreach ($batch as $row) {
		$placeholders[] = '(?,?,?,?)';
		$types .= 'iiss'; // id=int, asn=int, country=string, username=string
		$params[] = (int)$row['id_entry'];
		$params[] = (int)$row['asn'];
		$params[] = $row['country'];
		$params[] = $row['username'];
	}

	$sql = '
		INSERT INTO ' . $prefix . 'wala_web_access_log (id_entry, asn, country, username)
		VALUES ' . implode(',', $placeholders) . '
		ON DUPLICATE KEY UPDATE
			asn = VALUES(asn),
			country = VALUES(country),
			username = VALUES(username)';

	$stmt = $db->prepare($sql);
	if (!$stmt) {
		throw new WebAccessLogPrepareException('Prepare failed for upsert', [
			'error' => $db->error,
			'sql' => $sql
		]);
	}

	if (!$stmt->bind_param($types, ...$params)) {
		throw new WebAccessLogExecuteException('bind_param failed for upsert', [
			'error' => $stmt->error,
			'types' => $types,
			'sample_params' => array_slice($params, 0, 8)
		]);
	}

	if (!$stmt->execute()) {
		throw new WebAccessLogExecuteException('Execute failed for upsert', [
			'error' => $stmt->error,
			'sql' => $sql
		]);
	}

	$stmt->close();
}

/**
 * Debug function: shows parameter values and their types
 *
 * @param string $types  MySQLi bind_param type string, e.g. 'ississ'
 * @param array  $params Array of parameter values
 */
function debugBindParams(string $types, $params) {
    $n = strlen($types);
    $str = '';
    if ($n !== count($params)) {
        $str .= "⚠️ Warning: types length ($n) does not match params count (" . count($params) . ")\n";
    }

    $str .= "=== Debug Bind Params ===\n";
    for ($i = 0; $i < min($n, count($params)); $i++) {
        $typeChar = $types[$i];
        $value = $params[$i];

        switch ($typeChar) {
            case 'i': $typeName = 'integer'; break;
            case 'd': $typeName = 'double'; break;
            case 's': $typeName = 'string'; break;
            case 'b': $typeName = 'blob'; break;
            default:  $typeName = 'unknown'; break;
        }

        $str .= "Param #$i: value=" . var_export($value, true) . ", type='$typeChar' ($typeName)\n";
    }
    return $str . "=========================\n";
}

/**
 * Interpolate bound parameters into a SQL string for debug purposes.
 *
 * WARNING: Do not execute the result — this is for logging only!
 *
 * @param string $query SQL with ? placeholders
 * @param array  $params Parameters bound to the statement
 * @return string
 */
function interpolateQuery($query, $params) {
    $escapedParams = array_map(function ($param) {
        if (is_null($param)) return 'NULL';
        if (is_numeric($param)) return $param;
        return "'" . addslashes($param) . "'";
    }, $params);

    $parts = explode('?', $query);
    $rebuilt = '';
    foreach ($parts as $i => $part) {
        $rebuilt .= $part;
        if (isset($escapedParams[$i])) {
            $rebuilt .= $escapedParams[$i];
        }
    }
    return $rebuilt;
}
