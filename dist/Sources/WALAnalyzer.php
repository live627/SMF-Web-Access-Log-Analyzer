<?php
/**
 *	Main logic for the Web Access Log Analyzer mod for SMF..
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
 * WALA custom error handler.
 *
 * Captures PHP errors into a global array for debugging or logging.
 *
 * @param int $errno The level of the error raised
 * @param string $errstr The error message
 * @param string $errfile The filename the error was raised in
 * @param int $errline The line number the error was raised at
 *
 * @return bool Always true to prevent PHP default handler
 */
function wala_error_handler($errno, $errstr, $errfile, $errline) {
	global $wala_errors;

	// Initialize global if not yet set
	if (!isset($wala_errors) || !is_array($wala_errors)) {
		$wala_errors = [];
	}

	// Get error type name
	switch ($errno) {
		case E_ERROR:               $type = 'Fatal Error'; break;
		case E_WARNING:             $type = 'Warning'; break;
		case E_PARSE:               $type = 'Parse Error'; break;
		case E_NOTICE:              $type = 'Notice'; break;
		case E_CORE_ERROR:          $type = 'Core Error'; break;
		case E_CORE_WARNING:        $type = 'Core Warning'; break;
		case E_COMPILE_ERROR:       $type = 'Compile Error'; break;
		case E_COMPILE_WARNING:     $type = 'Compile Warning'; break;
		case E_USER_ERROR:          $type = 'User Error'; break;
		case E_USER_WARNING:        $type = 'User Warning'; break;
		case E_USER_NOTICE:         $type = 'User Notice'; break;
		case E_STRICT:              $type = 'Strict Notice'; break;
		case E_RECOVERABLE_ERROR:   $type = 'Recoverable Error'; break;
		case E_DEPRECATED:          $type = 'Deprecated'; break;
		case E_USER_DEPRECATED:     $type = 'User Deprecated'; break;
		default:                    $type = 'Unknown Error'; break;
	}

	// Capture error data
	$wala_errors[] = [
		'type' => $type,
		'errno' => $errno,
		'message' => $errstr,
		'file' => $errfile,
		'line' => $errline,
		'timestamp' => microtime(true),
	];

	// Optional: also echo for development
	// echo "[{$type}] $errstr in $errfile on line $errline\n";

	// Returning true prevents the PHP internal error handler from running
	return true;
}

/**
 * wala_main - action.
 *
 * Primary action called from the admin menu for managing WALA loads & reports.
 * Sets subactions & list columns & figures out if which subaction to call.
 *
 * Action: admin
 * Area: wala
 *
 * @return null
 *
 */
function wala_main() {
	global $txt, $context, $sourcedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Stuff we'll need around...
	loadLanguage('WALAnalyzer');
	loadCSSFile('walanalyzer.css');

	// Setup the template stuff we'll need.
	loadTemplate('WALAnalyzerMaint');

	// Everyone needs this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

	// Sub actions...
	$subActions = array(
		'load' => 'wala_load',
		'reports' => 'wala_reports',
	);

	// Pick the correct sub-action.
	if (isset($_REQUEST['sa']) && isset($subActions[$_REQUEST['sa']]))
		$context['sub_action'] = $_REQUEST['sa'];
	else
		$context['sub_action'] = 'load';

	$_REQUEST['sa'] = $context['sub_action'];

	// This uses admin tabs
	$context[$context['admin_menu_name']]['tab_data']['title'] = $txt['wala_title'];

	// Use the short description when viewing reports...
	if ($context['sub_action'] == 'load')
		$context[$context['admin_menu_name']]['tab_data']['description'] = $txt['wala_desc'];
	else
		$context[$context['admin_menu_name']]['tab_data']['description'] = $txt['wala_desc_short'];

	$context['page_title'] = $txt['wala_title'];
	call_helper($subActions[$context['sub_action']]);
}

/**
 * wala_load - page to load WALA with asn & country lookups & the web access log.
 *
 * Action: admin
 * Area: wala
 * Subaction: load
 *
 * @return null
 *
 */
function wala_load() {
	global $txt, $context, $sourcedir, $scripturl, $modSettings;

	// You have to be able to admin the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession('get');

	// Base max chunk size on max post size & upload_max_filesize, whichever is lower...
	// Default to 512K if not otherwise found.
	$post_max_size = trim(ini_get('post_max_size'));
	if (empty($post_max_size))
		$post_max_size = 1024*512;
	else {
		$unit = strtoupper(substr($post_max_size, -1));
		$value = (int) substr($post_max_size, 0, -1);
		if ($unit === 'G')
			$post_max_size = $value * 1024**3;
		elseif ($unit === 'M')
			$post_max_size = $value * 1024**2;
		elseif ($unit === 'K')
			$post_max_size = $value * 1024;
		else
			$post_max_size = (int) $post_max_size;
	}

	$upload_max_filesize = trim(ini_get('upload_max_filesize'));
	if (empty($upload_max_filesize))
		$upload_max_filesize = 1024*512;
	else {
		$unit = strtoupper(substr($upload_max_filesize, -1));
		$value = (int) substr($upload_max_filesize, 0, -1);
		if ($unit === 'G')
			$upload_max_filesize = $value * 1024**3;
		elseif ($unit === 'M')
			$upload_max_filesize = $value * 1024**2;
		elseif ($unit === 'K')
			$upload_max_filesize = $value * 1024;
		else
			$upload_max_filesize = (int) $upload_max_filesize;
	}

	// Need elbow room, lotsa other gunk in there...
	$wala_chunk_size = (int) (min($upload_max_filesize, $post_max_size) * 0.9);

	// JS vars for user info display
	addJavaScriptVar('wala_chunk_size', $wala_chunk_size, false);
	addJavaScriptVar('wala_str_loader', $txt['wala_loader'], true);
	addJavaScriptVar('wala_str_upprep', $txt['wala_upprep'], true);
	addJavaScriptVar('wala_str_uploaded', $txt['wala_uploaded'], true);
	addJavaScriptVar('wala_str_prep', $txt['wala_prep'], true);
	addJavaScriptVar('wala_str_imported', $txt['wala_imported'], true);
	addJavaScriptVar('wala_str_attribution', $txt['wala_attribution'], true);
	addJavaScriptVar('wala_str_done', $txt['wala_done'], true);
	addJavaScriptVar('wala_str_success', $txt['wala_success'], true);
	addJavaScriptVar('wala_str_failed', $txt['wala_failed'], true);
	addJavaScriptVar('wala_str_error_chunk', $txt['wala_error_chunk'], true);

	// For file xfers
	loadJavaScriptFile('wala_file_xfers.js');

	// Load up context with the file status data
	$status_info = get_status();
	foreach ($status_info AS $table) {
		$context['wala_status'][$table['file_type']]['file_name'] = $table['file_name'];
		$context['wala_status'][$table['file_type']]['last_proc_time'] = !empty($table['last_proc_time']) ? timeformat($table['last_proc_time']) : '';
	}

	// Set up some basics....
	$context['url_start'] = '?action=admin;area=wala;sa=load';
	$context['page_title'] = $txt['wala_load'];
	$context['sub_template'] = 'wala_load';
}

/**
 * wala_reports - page to let you run the reports.
 *
 * Action: admin
 * Area: wala
 * Subaction: reports
 *
 * @return null
 *
 */
function wala_reports() {
	global $context, $smcFunc, $txt;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Array with available reports
	// Note some specific mysql syntax is xlated to pg later (e.g., from_unixtime())
	$context['wala_reports'] = array(
		'wala_rpt_reqsxcountryui' => array(
			'hdr' => array('total requests', 'blocked', 'unblocked', 'country', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked, country FROM {db_prefix}wala_web_access_log GROUP BY country), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, country FROM {db_prefix}wala_members GROUP BY country) SELECT waltots.requests, waltots.blocked, waltots.unblocked, waltots.country, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots LEFT JOIN memtots ON (waltots.country = memtots.country) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_reqsxasnui' => array(
			'hdr' => array('total requests', 'blocked', 'unblocked', 'asn', 'asn name', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked, asn FROM {db_prefix}wala_web_access_log GROUP BY asn), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, asn FROM {db_prefix}wala_members GROUP BY asn) SELECT waltots.requests, waltots.blocked, waltots.unblocked, waltots.asn, a.asn_name, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots INNER JOIN {db_prefix}wala_asns a ON (waltots.asn = a.asn) LEFT JOIN memtots ON (waltots.asn = memtots.asn) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_reqsxagent' => array(
			'hdr' => array('agent', 'total requests', 'blocked', 'unblocked'),
			'sql' =>'SELECT agent, COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked FROM {db_prefix}wala_web_access_log GROUP BY agent ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_reqsxuser' => array(
			'hdr' => array('username', 'total requests', 'blocked', 'unblocked'),
			'sql' =>'SELECT username, COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked FROM {db_prefix}wala_web_access_log GROUP BY username ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_reqsxbrowser' => array(
			'hdr' => array('browser', 'total requests', 'blocked', 'unblocked'),
			'sql' =>'SELECT browser_ver, COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked FROM {db_prefix}wala_web_access_log GROUP BY browser_ver ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_ipsxcountry' => array(
			'hdr' => array('country', 'total ips', 'blocked', 'unblocked'),
			'sql' =>'SELECT country, COUNT(DISTINCT ip_packed) AS ips, COUNT(DISTINCT CASE WHEN status = 403 OR status = 429 THEN ip_packed ELSE NULL END) AS blocked, COUNT(DISTINCT CASE WHEN status = 403 OR status = 429 THEN NULL ELSE ip_packed END) AS unblocked FROM {db_prefix}wala_web_access_log GROUP BY country ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_ipsxasn' => array(
			'hdr' => array('asn', 'asn name', 'total ips', 'blocked', 'unblocked'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(DISTINCT ip_packed) AS ips, COUNT(DISTINCT CASE WHEN status = 403 OR status = 429 THEN ip_packed ELSE NULL END) AS blocked, COUNT(DISTINCT CASE WHEN status = 403 OR status = 429 THEN NULL ELSE ip_packed END) AS unblocked FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) GROUP BY a.asn ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_likesxcountry' => array(
			'hdr' => array('country', 'total view likes', 'blocked', 'unblocked'),
			'sql' =>'SELECT country, COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked FROM {db_prefix}wala_web_access_log WHERE request LIKE \'%action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY country ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_likesxasn' => array(
			'hdr' => array('asn', 'asn name', 'total view likes', 'blocked', 'unblocked'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(*) AS requests, COUNT(CASE WHEN status = 403 OR status = 429 THEN 1 ELSE NULL END) AS blocked, COUNT(CASE WHEN status = 403 OR status = 429 THEN NULL ELSE 1 END) AS unblocked FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) WHERE request LIKE \'%action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY a.asn ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_userxasn' => array(
			'hdr' => array('asn', 'asn name', 'users'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(*) AS users FROM {db_prefix}wala_members m INNER JOIN {db_prefix}wala_asns a ON (m.asn = a.asn) GROUP BY a.asn, a.asn_name ORDER BY users DESC LIMIT 500',
		),
		'wala_rpt_userxcountry' => array(
			'hdr' => array('country', 'users'),
			'sql' => 'SELECT country, COUNT(*) AS users FROM {db_prefix}wala_members GROUP BY country ORDER BY users DESC LIMIT 500',
		),
	);

	// Confirm they're OK being here...
	if (!empty($_POST))
		checkSession('post');

	// Report request?
	$context['wala_report_detail'] = array();
	if (!empty($_POST)) {
		// Make sure it's a valid request...
		if (!empty($_POST['wala_report_selection']) && array_key_exists($_POST['wala_report_selection'], $context['wala_reports'])) {
			$context['wala_report_detail'] = wala_report_request($context['wala_reports'][$_POST['wala_report_selection']]['sql']);
			$context['wala_report_hdr'] = $context['wala_reports'][$_POST['wala_report_selection']]['hdr'];
			$context['wala_report_selected'] = $_POST['wala_report_selection'];
		}
	}

	// Set up some basics....
	$context['url_start'] = '?action=admin;area=wala;sa=reports';
	$context['page_title'] = $txt['wala_reports'];
	$context['sub_template'] = 'wala_reports';
}

/**
 * WALA chunk response - subaction for uploaded file chunk.
 * Used when loading dbip_asn, dbip_country & the access log.
 * Load the file chunk sent by the fetch api.
 *
 * Action: xmlhttp
 * Subaction: walachunk
 *
 * @return null
 *
 */
function wala_chunk() {
	global $context, $cachedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	// if file system or post issues encountered, return a 500
	$issues = false;

	// Let's use our own subdir...
	$temp_dir = $cachedir . '/wala';
	if (!is_dir($temp_dir)) {
		if (mkdir($temp_dir, 0755) === false)
			$issues = true;
	}

	$file_index = 0;
	if (isset($_POST['index']) && is_numeric($_POST['index']))
		$file_index = $_POST['index'];
	else
		$issues = true;

	$file_type = '';
	if (isset($_POST['file_type']) && is_string($_POST['file_type']))
		$file_type = $_POST['file_type'];
	else
		$issues = true;

	$issues = !$issues && !move_uploaded_file($_FILES['chunk']['tmp_name'], $temp_dir . '/' . $file_type . '.chunk-' . $file_index);

	// For a simple generic yes/no response
	$context['sub_template'] = 'generic_xml';

	if ($issues) {
		$context['xml_data'][] = array('value' => 'FAILURE');
		send_http_status(500);
	}
	else
		$context['xml_data'][] = array('value' => 'OK');
}

/**
 * WALA_prep - subaction to combine the gz chunks, decompress & prep new csv chunks for import.
 * Used when loading dbip_asn, dbip_country & the access log.
 *
 * Action: xmlhttp
 * Subaction: walaprep
 *
 * @return null
 *
 */
function wala_prep() {
	global $context, $txt, $sourcedir, $cachedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	set_error_handler(wala_error_handler(...));
	$issues = false;

	// Make sure you got all the pieces...
	$temp_dir = $cachedir . '/wala';
	if (!is_dir($temp_dir))
		$issues = true;

	$file_name = '';
	if (isset($_POST['name']) && is_string($_POST['name']))
		$file_name = $_POST['name'];
	else
		$issues = true;

	$total_chunks = 0;
	if (isset($_POST['total_chunks']) && is_numeric($_POST['total_chunks']))
		$total_chunks = $_POST['total_chunks'];
	else
		$issues = true;

	$file_type = '';
	if (isset($_POST['file_type']) && is_string($_POST['file_type']))
		$file_type = $_POST['file_type'];
	else
		$issues = true;

	$final_file_name = $temp_dir . '/' . $file_type;
	$final_file = fopen($final_file_name, 'w');
	if ($final_file === false)
		$issues = true;

	for ($i = 1; $i <= $total_chunks; $i++) {
		$fp_in = fopen($final_file_name . '.chunk-'. $i, 'r');
		if ($fp_in === false) {
			$issues = true;
			break;
		}
		if (stream_copy_to_stream($fp_in, $final_file) === false) {
			$issues = true;
		}
		fclose($fp_in);
		unlink($final_file_name . '.chunk-'. $i);
	}

	fclose($final_file);

	// Now that we have a readable .gz, break it up into .csvs
	static $commit_rec_count = 25000;
	$reccount = 0;
	$index = 1;

	if (!$issues && $file_type === 'log') {
		$fpgz = gzopen($final_file_name, 'r');
		$fpcsv = fopen($final_file_name . '.csv-chunk-' . $index, 'w');

		$buffer = fgets($fpgz);
		while ($buffer !== false) {
			$reccount++;
			if ($reccount >= $commit_rec_count) {
				fclose($fpcsv);
				$reccount = 0;
				$index++;
				$fpcsv = fopen($final_file_name . '.csv-chunk-' . $index, 'w');
			}
			fwrite($fpcsv, $buffer);
			$buffer = fgets($fpgz);
		}
		fclose($fpcsv);
		gzclose($fpgz);
	}

	require_once($sourcedir . '/WALAnalyzerModel.php');

	if (!$issues) {
		if ($file_type === 'asn') {
			$issues = wala_load_asn($temp_dir);

			if (!$issues) {
				update_status('asn', $file_name, time());
			} else {
				update_status('asn');
			}
		}
		elseif ($file_type === 'country') {
			$issues = wala_load_country($temp_dir);

			if (!$issues) {
				update_status('country', $file_name, time());
			} else {
				update_status('country');
			}
		}
		elseif ($file_type === 'log') {
			update_status('log');
			truncate_web_access_log();
		}

		// Don't need this anymore...
		unlink($final_file_name);
	}

	// For a simple generic yes/no response
	$context['sub_template'] = 'generic_xml';

	if ($issues) {
		$context['xml_data'][] = array('value' => 'FAILURE');
		send_http_status(500);
	}
	else
		$context['xml_data'][] = array('value' => 'OK ' . $index . ' chunks');

	if (isset($GLOBALS['wala_errors'])) {
		foreach ($GLOBALS['wala_errors'] as $error) {
			$context['xml_data']['errors'] = array(
				'identifier' => 'error',
				'children' => array(
					array(
						'value' => $error['message'],
					),
				),
			);
		}
	}
}

/**
 * WALA_import - subaction to import the csv chunks.
 * Used when loading dbip_asn, dbip_country & the access log.
 *
 * Action: xmlhttp
 * Subaction: walaimport
 *
 * @return null
 *
 */
function wala_import() {
	global $context, $txt, $sourcedir, $cachedir;

	// Debug timer helper
	$gstart = microtime(true);
	function tdump($label, $start, $extra = null) {
		static $first = null;
		if ($first === null) $first = $start;
		$elapsed = microtime(true) - $start;
		$total = microtime(true) - $first;
		echo "\n=== {$label} ===\n";
		echo sprintf("Elapsed: %.6f s | Total since start: %.6f s\n", $elapsed, $total);
		if ($extra !== null) {
			echo "Extra: ";
			if (is_array($extra) || is_object($extra))
				print_r($extra);
			else
				echo $extra . "\n";
		}
		echo "------------------------\n";
	}

	tdump('Start wala_import()', $gstart);

	// You have to be able to moderate the forum to do this.
	$start = microtime(true);
	isAllowedTo('admin_forum');
	tdump('Check admin permissions', $start);

	$start = microtime(true);
	checkSession();
	tdump('Check session', $start);

	$issues = false;

	$start = microtime(true);
	require_once($sourcedir . '/WALAnalyzerModel.php');
	tdump('Load WALAnalyzerModel', $start);

	// Check temp directory
	$start = microtime(true);
	$temp_dir = $cachedir . '/wala';
	if (!is_dir($temp_dir)) $issues = true;
	tdump('Check temp_dir', $start, ['temp_dir' => $temp_dir]);

	// Validate POST params
	$start = microtime(true);
	$file_name = isset($_POST['name']) && is_string($_POST['name']) ? $_POST['name'] : ($issues = true);
	$total_chunks = isset($_POST['total_chunks']) && is_numeric($_POST['total_chunks']) ? $_POST['total_chunks'] : ($issues = true);
	$index = isset($_POST['index']) && is_numeric($_POST['index']) ? $_POST['index'] : ($issues = true);
	$file_type = isset($_POST['file_type']) && is_string($_POST['file_type']) ? $_POST['file_type'] : ($issues = true);
	tdump('Validate POST parameters', $start, compact('file_name','total_chunks','index','file_type'));

	// Process log file import
	if (!$issues && $file_type === 'log') {
		$start = microtime(true);
		start_transaction();
		tdump('Start transaction', $start);

		$start2 = microtime(true);
		$issues = wala_load_log_conditional($temp_dir . '/log.csv-chunk-' . $index);
		tdump('Load log chunk', $start2, ['chunk_file' => $temp_dir . '/log.csv-chunk-' . $index]);

		$start3 = microtime(true);
		commit();
		tdump('Commit transaction', $start3);
	}

	// Prepare XML response
	$start = microtime(true);
	$context['sub_template'] = 'generic_xml';
	if ($issues) {
		$context['xml_data'][] = ['value' => 'FAILURE'];
		send_http_status(500);
	} else {
		$context['xml_data'][] = ['value' => 'OK'];
	}
	tdump('Prepare XML response', $start);

	tdump('End wala_import()', $gstart);
}

/**
 * WALA_members - subaction to load the wala member reporting table from smf member table in chunks.
 *
 * Action: xmlhttp
 * Subaction: walamemb
 *
 * @return null
 *
 */
function wala_members() {
	global $context, $txt, $sourcedir, $cachedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	// If file system or post issues encountered, return a 500
	$issues = false;

	$index = 0;
	if (isset($_POST['index']) && is_numeric($_POST['index']))
		$index = (int) $_POST['index'];
	else
		$issues = true;

	// Gonna need this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

	// How many members total?
	$reccount = count_smf_members();

	// How many chunks total?  Not too big...
	$commit_rec_count = ceil($reccount/20);
	if ($commit_rec_count > 20000)
		$commit_rec_count = 20000;
	$chunkct = ceil($reccount/$commit_rec_count);

	// Truncate target table...
	if (!$issues && ($index ==	1)) {
		start_transaction();
		truncate_members();
		commit();
	}

	// Copy over a set of members...
	// Disable autocommits for mass inserts (can hide errors, though...)
	$start = ($index - 1) * $commit_rec_count;
	$inserts = array();
	if (!$issues) {
		$inserts = get_smf_members($start, $commit_rec_count);
		start_transaction();
		insert_members($inserts);
		commit();
	}

	// For a simple generic yes/no response
	$context['sub_template'] = 'generic_xml';

	if ($issues) {
		$context['xml_data'][] = array('value' => 'FAILURE');
		send_http_status(500);
	}
	else
		$context['xml_data'][] = array('value' => 'OK ' . $chunkct . ' chunks');
}

/**
 * WALA_member_attr - load attributes to the newly loaded wala member file.
 * Looking up by IP, load ASN & Country.
 *
 * Action: xmlhttp
 * Subaction: walamattr
 *
 * @return null
 *
 */
function wala_memb_attr() {

    global $context, $sourcedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	// If file system or post issues encountered, return a 500
	$issues = false;

	$index = 0;
	if (isset($_POST['index']) && is_numeric($_POST['index']))
		$index = (int) $_POST['index'];
	else
		$issues = true;

	// Gonna need this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

	if (!$issues) {
		// How many chunks total?  Not too big...
		// Even a small chunk of users, sorted by IP, can retrieve a large # of asn/country rows
		$reccount = count_smf_members();
		$commit_rec_count = ceil($reccount/20);
		if ($commit_rec_count > 20000)
			$commit_rec_count = 20000;
		$chunkct = ceil($reccount/$commit_rec_count);

		$offset = $index * $commit_rec_count;
		$limit = $commit_rec_count;
		$members = get_wala_members($offset, $limit);
		$min_ip_packed_1 = $members[0]['ip_packed'];
		$max_ip_packed_1 = end($members)['ip_packed'];

		// If jumping from ipv4 to ipv6, split 'em...
		// Range can be just too big...
		if (strlen($min_ip_packed_1) == strlen($max_ip_packed_1)) {
			load_asn_cache($min_ip_packed_1, $max_ip_packed_1, true);
			load_country_cache($min_ip_packed_1, $max_ip_packed_1, true);
		}
		else {
			$max_ip_packed_2 = $max_ip_packed_1;
			$max_ip_packed_1 = null;
			$min_ip_packed_2 = null;
			foreach ($members AS $member) {
				if (strlen($member['ip_packed']) == 4) {
					$max_ip_packed_1 = $member['ip_packed'];
				}
				elseif ((strlen($member['ip_packed']) == 16) && ($min_ip_packed_2 === null)) {
					$min_ip_packed_2 = $member['ip_packed'];
					break;
				}
			}
			// ipv4...
			load_asn_cache($min_ip_packed_1, $max_ip_packed_1, true);
			load_country_cache($min_ip_packed_1, $max_ip_packed_1, true);
			// ipv6...
			load_asn_cache($min_ip_packed_2, $max_ip_packed_2, false);
			load_country_cache($min_ip_packed_2, $max_ip_packed_2, false);
		}

		start_transaction();
		foreach ($members AS $member_info) {
			$member_info['asn'] = get_asn($member_info['ip_packed']);
			$member_info['country'] = binary_search_data($member_info['ip_packed']);
			update_wala_members($member_info);
		}
		commit();
	}

	// If we're done, update the file status info...
	if (!$issues && ($index == $chunkct - 1)) {
		update_status('member', '---', time());
	}

	// For a simple generic yes/no response
	$context['sub_template'] = 'generic_xml';

	if ($issues) {
		$context['xml_data'][] = array('value' => 'FAILURE');
		send_http_status(500);
	}
	else
		$context['xml_data'][] = array('value' => 'OK ' . $chunkct . ' chunks');
}

/**
 * WALA_log_attr - load attributes to the newly loaded log file
 * Looking up by IP, load ASN, Country & member.
 *
 * Action: xmlhttp
 * Subaction: walalattr
 *
 * @return null
 *
 */
function wala_log_attr() {
	global $context, $txt, $sourcedir, $cachedir;

	isAllowedTo('admin_forum');
	checkSession();

	set_error_handler(wala_error_handler(...));
	$issues = false;

	$temp_dir = $cachedir . '/wala';
	if (!is_dir($temp_dir))
		$issues = true;

	$index = isset($_POST['index']) && is_numeric($_POST['index']) ? (int) $_POST['index'] : 0;
	$file_name = isset($_POST['name']) && is_string($_POST['name']) ? $_POST['name'] : '';
	if ($file_name === '' || $issues)
		$issues = true;

	require_once($sourcedir . '/WALAnalyzerModel.php');

	if (!$issues) {
		$gstart = microtime(true);

		// Use readable timedump instead of var_dump
		function tdump($label, $start, $extra = null) {
			static $first = null;
			$elapsed = microtime(true) - $start;
			$total = microtime(true) - $first;
			echo "\n=== {$label} ===\n";
			$first = $start;
			echo sprintf("Elapsed: %.6f s | Total since start: %.6f s\n", $elapsed, $total);
			if ($extra !== null) {
				echo "Extra: ";
				if (is_array($extra) || is_object($extra))
					print_r($extra);
				else
					echo $extra . "\n";
			}
			echo "------------------------\n";
		}

		$reccount = count_web_access_log();
		tdump('After count_web_access_log()', $gstart, ['reccount' => $reccount]);

		$commit_rec_count = min(5000, ceil($reccount / 20));
		$chunkct = ceil($reccount / $commit_rec_count);

		$offset = $index * $commit_rec_count;
		$limit = $commit_rec_count;
		$log = get_web_access_log($offset, $limit);
		tdump('After get_web_access_log()', $gstart, ['offset' => $offset, 'limit' => $limit, 'count' => count($log)]);

		load_member_cache($log[0]['ip_packed'], end($log)['ip_packed']);
		tdump('After load_member_cache()', $gstart);

		// Min/max IP boundaries
		$min_ipv4 = $max_ipv4 = $min_ipv6 = $max_ipv6 = null;
		$count = count($log);

		if (strlen($log[0]['ip_packed']) === 4)
			$min_ipv4 = $log[0]['ip_packed'];

		for ($i = $count - 1; $i >= 0; $i--) {
			if (strlen($log[$i]['ip_packed']) === 16) {
				$min_ipv6 ??= $log[$i]['ip_packed'];
				$max_ipv6 ??= $log[$i]['ip_packed'];
			} else {
				$max_ipv4 = $log[$i]['ip_packed'];
				break;
			}
		}

		global $ord_cache;
		$ord_cache = array_flip(range("\0", "\xFF"));

		tdump('After preparing ord_cache()', $gstart);

		if ($min_ipv4 !== null) {
			$ipv4_asns = wala_load_buffer($temp_dir . '/asn-4');
			$ipv4_asns_jump_table = buildJumpTable($ipv4_asns, 4);
			tdump('IPv4 ASN buffers loaded', $gstart);
		}
		if ($min_ipv6 !== null) {
			$ipv6_asns = wala_load_buffer($temp_dir . '/asn-16');
			$ipv6_asns_jump_table = buildJumpTable($ipv6_asns, 16);
			tdump('IPv6 ASN buffers loaded', $gstart);
		}
		if ($min_ipv4 !== null) {
			$ipv4_countries = wala_load_buffer($temp_dir . '/country-4');
			$ipv4_countries_jump_table = buildJumpTable($ipv4_countries, 4);
			tdump('IPv4 country buffers loaded', $gstart);
		}
		if ($min_ipv6 !== null) {
			$ipv6_countries = wala_load_buffer($temp_dir . '/country-16');
			$ipv6_countries_jump_table = buildJumpTable($ipv6_countries, 16);
			tdump('IPv6 country buffers loaded', $gstart);
		}

		// Timers
		$cumulative = ['asn' => 0.0, 'country' => 0.0, 'username' => 0.0, 'update' => 0.0];

		foreach ($log as &$entry_info) {
			if (strlen($entry_info['ip_packed']) === 4) {
				$start = microtime(true);
				$entry_info['asn'] = binary_search_data($entry_info['ip_packed'], $ipv4_asns_jump_table, $ipv4_asns, 12);
				$cumulative['asn'] += microtime(true) - $start;

				$start = microtime(true);
				$entry_info['country'] = binary_search_data($entry_info['ip_packed'], $ipv4_countries_jump_table, $ipv4_countries, 10);
				$cumulative['country'] += microtime(true) - $start;
			} else {
				$start = microtime(true);
				$entry_info['asn'] = binary_search_data($entry_info['ip_packed'], $ipv6_asns_jump_table, $ipv6_asns, 36);
				$cumulative['asn'] += microtime(true) - $start;

				$start = microtime(true);
				$entry_info['country'] = binary_search_data($entry_info['ip_packed'], $ipv6_countries_jump_table, $ipv6_countries, 34);
				$cumulative['country'] += microtime(true) - $start;
			}

			$start = microtime(true);
			$entry_info['username'] = get_username($entry_info['ip_packed']);
			$cumulative['username'] += microtime(true) - $start;
		}
		var_dump($GLOBALS['RS']);

		start_transaction();
		tdump('After start_transaction()', $gstart);

		$start = microtime(true);
		update_web_access_log2($log);
		$cumulative['update'] += microtime(true) - $start;
		tdump('After update_web_access_log2()', $gstart, $cumulative);

		commit();
		tdump('After commit()', $gstart, ['chunk' => $index]);
	}

	$context['sub_template'] = 'generic_xml';
	if ($issues) {
		$context['xml_data'][] = ['value' => 'FAILURE'];
		send_http_status(500);
	} else {
		$context['xml_data'][] = ['value' => 'OK ' . ($chunkct ?? '?') . ' chunks'];
	}

	if (isset($GLOBALS['wala_errors'])) {
		foreach ($GLOBALS['wala_errors'] as $error) {
			$context['xml_data']['errors'] = [
				'identifier' => 'error',
				'children' => [['value' => $error['message']]],
			];
		}
	}
}

/**
 * Load a packed binary file into memory and return its buffer.
 *
 * @param string $filename Path to the ASN binary file (asn-4 or asn-16)
 *
 * @return string|false Binary buffer on success, false on failure
 */
function wala_load_buffer($filename)
{
	if (!is_readable($filename)) {
		return false;
	}

	$buffer = @file_get_contents($filename);
	if ($buffer === false) {
		return false;
	}

	return $buffer;
}

/**
 * Build jump table for packed IP ranges.
 *
 * Each slot points to the first record whose ip_to >= prefix boundary.
 *
 * For IPv4 → 256 entries (1 per /8)
 * For IPv6 → 65536 entries (1 per /16)
 *
 * @param string $data Binary blob (packed ranges)
 * @param int $len IP length (4 or 16)
 * @return array<int,int> Jump table (prefix => record index)
 */
function buildJumpTable($data, $len)
{
	global $ord_cache;

	$record_size = $len * 2 + 2;
	$record_count = (int)(strlen($data) / $record_size);

	$table_size = $len === 4 ? 256 : 65536;
	$jump_table = array_fill(0, $table_size, $record_count); // default to end

	$prefix = 0;
	for ($i = 0, $j = 0; $i < $record_count; $i++, $j += $record_size) {
		// Extract prefix index
		if ($len === 4) {
			$prefix_val = $ord_cache[$data[$j + $len]];
		} else {
			$prefix_val = ($ord_cache[$data[$j + $len]] << 8) | $ord_cache[$data[$j + $len + 1]];
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
function binary_search_data(string $ip_packed, array $jump_table, string $data, int $record_size): string
{
	global $ord_cache;

	$len = strlen($ip_packed);
	$return_size = $record_size - $len * 2;
	$GLOBALS['RS'][$return_size]=$record_size ;
	$record_count = (int)(strlen($data) / $record_size);

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

		if (substr_compare($data, $ip_packed, $offset + $len, $len) < 0) {
			// The IP we’re searching for is above this range
			$low = $mid + 1;
		} elseif (substr_compare($data, $ip_packed, $offset, $len) > 0) {
			// The IP we’re searching for is below this range
			$high = $mid - 1; 
		} else {
			// The IP lies within the current range
			return substr($data, $offset + $len * 2, $return_size);
		}
	}

	return '';
}

/**
 * Load DBIP ASN data into binary form for IPv4 and IPv6.
 *
 * The CSV format is expected to have:
 *   0: ip_from
 *   1: ip_to
 *   2: asn_number
 *   3: asn_name
 *
 * For each record size (4 for IPv4, 16 for IPv6), this function writes a binary file
 * with records consisting of:
 *   [ip_from][ip_to][asn_number(4 bytes)]
 *
 * @param string $temp_dir Directory containing the gzipped ASN CSV (named 'asn')
 *
 * @return bool Any issues found
 */
function wala_load_asn($temp_dir) {
	if (($fp_in = gzopen($temp_dir . '/asn', 'r')) === false) {
		return true;
	}

	$inserts = [];

	foreach ([4, 16] as $record_size) {
		if (($fp_out = fopen($temp_dir . '/asn-' . $record_size, 'w')) === false) {
			gzclose($fp_in);
			return true;
		}

		while (($line = gzgets($fp_in)) !== false) {
			// Skip invalid or malformed lines
			if (substr_count($line, ',') < 4) {
				continue;
			}

			$ip_from_str = strtok($line, ',');
			$ip_to_str = strtok(',');
			$asn_num_str = strtok(',');
			$asn_name = strtok(',');

			$ip_from = @inet_pton($ip_from_str);
			$ip_to = @inet_pton($ip_to_str);

			if (!$ip_from || !$ip_to) {
				continue;
			}

			$len = strlen($ip_from);

			if ($len !== $record_size) {
				continue;
			}

			// ASN number as unsigned 32-bit int
			$asn_num = (int)$asn_num_str;
			$asn_bin = pack('N', $asn_num);

			$inserts[$asn_num] = trim($asn_name, '"');

			// Write packed data: [ip_from][ip_to][asn_num(4)]
			fwrite($fp_out, $ip_from . $ip_to . $asn_bin);
		}

		fclose($fp_out);
		gzrewind($fp_in);
	}

	gzclose($fp_in);

	insert_dbip_asn($inserts);

	return false;
}

/**
 * WALA_load_country - load a chunk of the dbip country file to db.
 *
 * Action: na - helper function
 *
 * @param string filename of chunk
 *
 * @return bool $issues_found
 *
 */
function wala_load_country($temp_dir) {
	if (($fp_in = gzopen($temp_dir . '/country', 'r')) !== false) {
		foreach ([4, 16] as $record_size) {
			if (($fp_out = fopen($temp_dir . '/country-' . $record_size, 'w')) !== false) {
				while (($line = gzgets($fp_in)) !== false) {
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

					fwrite($fp_out, $ip_from . $ip_to . substr($country, 0, 2));
				}

				fclose($fp_out);
				gzrewind($fp_in);
			}
		}

		gzclose($fp_in);
	}

	return false;
}
/**
 * Generator: yield each log row
 *
 * @param string $filename
 * @return Generator yields processed log rows
 */
function wala_load_log_generator(string $filename): Generator
{
	global $smcFunc;

	$fp = fopen($filename, 'r');
	if (!$fp) {
		return true;
	}

	$inserts = [];
	static $req_cache = [];
	static $agent_cache = [];
	static $browser_cache = [];

	$batch_size = 100;
	$batch_count = 0;
	$i = 0;

	while (($line = fgets($fp)) !== false) {
		if ($line === '') {
			continue;
		}

		if (strpos($line, '\\') !== false) {
			// Use str_getcsv for escaped/quoted fields
			$buffer = str_getcsv($line, ' ', '"', '\\');

			// Map expected fields from CSV
			if (count($buffer) < 10) {
				return true;
			}

			list($ip, $client, $requestor, $date_part, $tz_part, $request, $status, $size, $referrer, $user_agent) = $buffer;
		} else {
			// Fast, naive, brittle path with strtok
			$ip = strtok($line, ' ');
			$client = strtok(' ');
			$requestor = strtok(' ');
			$date_part = strtok(' ');
			$tz_part = strtok(' ');
			$request = strtok('"');
			$status = strtok(' ');
			$size = strtok(' ');
			$referrer = strtok('"');
			strtok('"');
			$user_agent = strtok('"');
		}

		// Validate and normalize
		if (!filter_var($ip, FILTER_VALIDATE_IP)) {
			trigger_error('Invalid IP: ' . $ip);
			return true;
		}

		if (!is_numeric($status) || !is_numeric($size)) {
			trigger_error('Values must be  numeric: ' . $ip);
			return true;
		}

		$dt_string = substr($date_part . ' ' .  $tz_part, 1, -1);
		$ts = parseApacheDateTimeImmCached($dt_string);
		if ($ts === false) {
			trigger_error('Invalid date: ' . $dt_string);
			return true;
		}

		// Caching lookups
		if (!isset($req_cache[$request])) {
			$req_cache[$request] = get_request_type($request);
		}
		if (!isset($agent_cache[$user_agent])) {
			$agent_cache[$user_agent] = get_agent($user_agent);
		}
		if (!isset($browser_cache[$user_agent])) {
			$browser_cache[$user_agent] = get_browser_ver($user_agent);
		}

		yield [
			$ip,
			$client,
			$requestor,
			substr($date_part, 1),
			substr($tz_part, 0, -1),
			$request,
			(int)$status,
			(int)$size,
			$referrer,
			$user_agent,
			$ip,
			$req_cache[$request],
			$agent_cache[$user_agent],
			$browser_cache[$user_agent],
			$ts,
		];
	}

	fclose($fp);
	unlink($filename);

	return false;
}

/**
 * Batch generator for log entries.
 *
 * @param Generator $generator
 * @param int $batch_size
 * @return Generator yields arrays of log entries
 */
function wala_log_batches(Generator $generator, int $batch_size = 100): Generator {
	$batch = [];
	foreach ($generator as $entry) {
		$batch[] = $entry;
		if (count($batch) >= $batch_size) {
			yield $batch;
			$batch = [];
		}
	}
	if (!empty($batch)) {
		yield $batch;
	}
}

/**
 * Insert log entries in batches only if DB type is NOT MySQL.
 *
 * @param string $filename
 * @param string $db_type
 */
function wala_load_log_conditional(string $filename) {
	global $smcFunc, $db_type;

	$generator = wala_load_log_generator($filename);

	start_transaction();

	if ($db_type === 'mysql') {
		smf_db_insert_bactches('insert',
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
			$generator,
			array('id_entry')
		);
	} else {
		// Other DB types: batch insert
		foreach (wala_log_batches($generator, 100) as $batch) {
			insert_log(iterator_to_array($batch));
		}
	}

	commit();
}

/**
 * Cached DateTimeImmutable approach.
 */
function parseApacheDateTimeImmCached($s) {
	static $day_cache = [];
	static $time_cache = [];

	// Expected format: 25/Oct/2025:12:34:56 +0000
	if (strlen($s) !== 26) {
		return false;
	}

	// Using fixed string offsets here is much faster than a regex
	$day_str = substr($s, 0, 11);   // "25/Oct/2025"
	$h = substr($s, 12, 2);         // "12"
	$i = substr($s, 15, 2);         // "34"
	$sec = substr($s, 18, 2);       // "56"
	$tz = substr($s, 20, 5);        // "+0000"

	$day_key = $day_str . $tz;
	$time_key = $h * 3600 + $i * 60 + $sec;

	if (!isset($day_cache[$day_key])) {
		$dti = DateTimeImmutable::createFromFormat('d/M/Y H:i:s O', $day_str . ' 00:00:00 ' . $tz);
		if (!$dti) {
			return false;
		}
		$day_cache[$day_key] = $dti->getTimestamp();
	}

	if (!isset($time_cache[$time_key])) {
		$time_cache[$time_key] = $time_key;
	}

	return $day_cache[$day_key] + $time_cache[$time_key];
}

/**
 * load_member_cache - load up the member cache.
 *
 * Action: na - helper function
 *
 * @params inet $min_ip_packed
 * @params inet $max_ip_packed
 *
 * @return void
 *
 */
function load_member_cache($min_ip_packed, $max_ip_packed) {
	global $member_cache;

	$member_cache = array();


	$start = microtime(true);

	$members = get_member_ips($min_ip_packed, $max_ip_packed);

	$total = microtime(true) - $start;
	printf("fetch mem ip took %.4f seconds\n", $total);
	$start = microtime(true);
	foreach ($members AS $member) {
		$member_cache[bin2hex($member['ip_packed'])] = $member['real_name'];
	}
	$total = microtime(true) - $start;
	printf("fetch mem ip took %.4f seconds\n", $total);
}

/**
 * get_username - look up the username from the member cache
 * Match smf_members by IP...  Imperfect, but close enough...
 *
 * Action: na - helper function
 *
 * @params inet $ip_packed
 *
 * @return string $username
 *
 */
function get_username($ip_packed) {
	global $member_cache;

	$name = 'Guest';
	$ip_hex = bin2hex($ip_packed);

	if (array_key_exists($ip_hex, $member_cache))
		$name = $member_cache[$ip_hex];

	return $name;
}

function get_request_type($request) {
	static $map = array(
		'area=alerts_popup'      => 'Alerts',
		'type=rss'               => 'RSS',
		'action=admin'           => 'Admin',
		'action=keepalive'       => 'Keepalive',
		'action=printpage'       => 'Print',
		'action=recent'          => 'Recent',
		'action=unread'          => 'Unread',
		'action=likes'           => 'Likes',
		'action=dlattach'        => 'Attach',
		'action=quotefast'       => 'Quote',
		'action=markasread'      => 'MarkRead',
		'action=quickmod2'       => 'Modify',
		'action=profile'         => 'Profile',
		'action=pm'              => 'PM',
		'action=xml'             => 'xml',
		'action=.xml'            => 'xml',
		'action=attbr'           => 'Attachment Browser',
		'action=search'          => 'Search',
		'action=signup'          => 'Signup',
		'action=register'        => 'Signup',
		'action=join'            => 'Signup',
		'action=login'           => 'Login',
		'action=logout'          => 'Logout',
		'action=verificationcode'=> 'Login',
		'.msg'                   => 'Message',
		'msg='                   => 'Message',
		'topic='                 => 'Topic',
		'board='                 => 'Board',
		';wwwRedirect'           => 'Redirect',
		'/smf/custom_avatar'     => 'Avatar',
		'/smf/cron.php?ts='      => 'Cron',
		'/smf/index.php '        => 'Board Index',
		'/smf/proxy.php'         => 'Proxy',
		'/smf/avatars'           => 'Avatar',
		'/smf/Smileys'           => 'Smileys',
		'/smf/Themes'            => 'Theme',
		'/favicon.ico'           => 'Favicon',
		'/robots.txt'            => 'robots.txt',
		'/sitemap'               => 'Sitemap',
		'/phpmyadmin'            => 'Admin',
		'/admin'                 => 'Admin',
	);

	static $regex = null;
	if ($regex === null) {
		$regex = $GLOBALS['modSettings']['wala_request_type_regex'] ?? null;
	}
	if ($regex === null) {
		// Build one giant alternation regex
		$regex = '/' . build_regex(array_keys($map), '/') . '/i';
		updateSettings(['wala_request_type_regex' =>  $regex]);
	}

	if (preg_match($regex, $request, $m)) {
		return $map[$m[0]] ?? 'Other';
	}

	return 'Other';
}

function get_agent($user_agent) {
	if ($user_agent === '-') {
		return 'BLANK';
	}

	$ua = strtolower($user_agent);

	static $map = array(
		'2ip bot' => '2ip bot', '360spider' => '360Spider', 'adsbot-google' => 'AdsBot-Google',
		'ahrefsbot' => 'AhrefsBot', 'aliyunsecbot' => 'AliyunSecBot', 'awario' => 'Awario',
		'amazonbot' => 'amazonbot', 'applebot' => 'applebot', 'archivebot' => 'ArchiveBot',
		'baiduspider' => 'BaiduSpider', 'bingbot' => 'bingbot', 'blexbot' => 'BLEXBot',
		'bravebot' => 'Bravebot', 'bytespider' => 'Bytespider', 'cincraw' => 'Cincraw',
		'claudebot' => 'claudebot', 'coccocbot' => 'coccocbot', 'commoncrawl' => 'commoncrawl',
		'dataforseo-bot' => 'dataforseo-bot', 'discordbot' => 'Discordbot',
		'domainstatsbot' => 'DomainStatsBot', 'dotbot' => 'DotBot', 'duckassistbot' => 'DuckAssistBot',
		'duckduckbot' => 'duckduckbot', 'duckduckgo-favicons-bot' => 'DuckDuckGo-Favicons-Bot',
		'facebookexternalhit' => 'facebookexternalhit', 'gaisbot' => 'Gaisbot',
		'googlebot' => 'Googlebot', 'googleother' => 'GoogleOther', 'google.com/bot' => 'google.com/bot',
		'hawaiibot' => 'HawaiiBot', 'iaskbot' => 'iAskBot', 'keys-so-bot' => 'keys-so-bot',
		'linerbot' => 'LinerBot', 'meta-externalagent' => 'meta-externalagent',
		'mixrankbot' => 'MixrankBot', 'mj12bot' => 'mj12bot', 'mojeekbot' => 'MojeekBot',
		'msnbot' => 'msnbot', 'openai' => 'openai', 'petalbot' => 'petalbot',
		'pinterestbot' => 'Pinterestbot', 'python-requests' => 'python-requests',
		'qwantbot' => 'Qwantbot', 'redditbot' => 'redditbot', 'ru_bot' => 'RU_Bot',
		'screaming frog seo spider' => 'Screaming Frog SEO Spider', 'seekportbot' => 'SeekportBot',
		'semrushbot' => 'SemrushBot', 'seznambot' => 'seznambot', 'sitelockspider' => 'SiteLockSpider',
		'slack-imgproxy' => 'Slack-ImgProxy', 'sogou' => 'Sogou', 'startmebot' => 'StartmeBot',
		'superbot' => 'SuperBot', 'telegrambot' => 'TelegramBot', 'thinkbot' => 'Thinkbot',
		'tiktokspider' => 'TikTokSpider', 'trendictionbot' => 'trendictionbot', 'twitterbot' => 'Twitterbot',
		'turnitinbot' => 'TurnitinBot', 'wellknownbot' => 'WellKnownBot', 'wirereaderbot' => 'WireReaderBot',
		'wpbot' => 'wpbot', 'yacybot' => 'yacybot', 'yandex' => 'yandex', 'yisouspider' => 'YisouSpider',
		'zoombot' => 'ZoomBot', 'zoominfobot' => 'zoominfobot',
	);

	static $regex = null;
	if ($regex === null) {
		$regex = $GLOBALS['modSettings']['wala_user_agent_regex'] ?? null;
	}
	if ($regex === null) {
		// Build one giant alternation regex
		$regex = '/' . build_regex(array_keys($map), '/') . '/i';
		updateSettings(['wala_user_agent_regex' =>  $regex]);
	}

	if (preg_match($regex, $ua, $m)) {
		return $map[$m[0]] ?? 'Other';
	}

	// Generic bot detection
	if (str_contains($ua, 'spider') || str_contains($ua, 'bot') || str_contains($ua, 'crawl')) {
		return 'Other bot';
	}

	return 'User';
}
function get_browser_ver($user_agent) {
	static $pattern = '/(?:(?:firefox|chrome|msie|safari|edg|edga|edgios|opera|vivaldi)\/\d{1,3}|mobile\/\d\d[a-z]\d\d\d\|safari\/\d{4,5})\b/i';

	if (preg_match($pattern, $user_agent, $m)) {
		return $m[0];
	}

	return '';
}
