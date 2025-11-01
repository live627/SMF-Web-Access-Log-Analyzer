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

	// Set the page title
	$context['page_title'] = $txt['wala_title'];

	// Finally fall through to what we are doing.
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
		'wala_rpt_ureqsxcountryui' => array(
			'hdr' => array('requests', 'country', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, country FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY country), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, country FROM {db_prefix}wala_members GROUP BY country)  SELECT waltots.requests, waltots.country, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots LEFT JOIN memtots ON (waltots.country = memtots.country) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_areqsxcountryui' => array(
			'hdr' => array('requests', 'country', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, country FROM {db_prefix}wala_web_access_log GROUP BY country), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, country FROM {db_prefix}wala_members GROUP BY country) SELECT waltots.requests, waltots.country, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots LEFT JOIN memtots ON (waltots.country = memtots.country) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_ureqsxasnui' => array(
			'hdr' => array('requests', 'asn', 'asn name', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, asn FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY asn), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, asn FROM {db_prefix}wala_members GROUP BY asn) SELECT waltots.requests, waltots.asn, a.asn_name, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots INNER JOIN {db_prefix}wala_asns a ON (waltots.asn = a.asn) LEFT JOIN memtots ON (waltots.asn = memtots.asn) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_areqsxasnui' => array(
			'hdr' => array('requests', 'asn', 'asn name', 'user count', 'last login'),
			'sql' =>'WITH waltots AS (SELECT COUNT(*) AS requests, asn FROM {db_prefix}wala_web_access_log GROUP BY asn), memtots AS (SELECT COUNT(*) AS user_count, MAX(last_login) AS last_user_login, asn FROM {db_prefix}wala_members GROUP BY asn) SELECT waltots.requests, waltots.asn, a.asn_name, memtots.user_count, FROM_UNIXTIME(memtots.last_user_login) AS last_user_login FROM waltots INNER JOIN {db_prefix}wala_asns a ON (waltots.asn = a.asn) LEFT JOIN memtots ON (waltots.asn = memtots.asn) ORDER BY waltots.requests DESC LIMIT 500',
		),
		'wala_rpt_ureqsxagent' => array(
			'hdr' => array('agent', 'requests'),
			'sql' =>'SELECT agent, COUNT(*) as requests FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY agent ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_areqsxagent' => array(
			'hdr' => array('agent', 'requests'),
			'sql' =>'SELECT agent, COUNT(*) as requests FROM {db_prefix}wala_web_access_log GROUP BY agent ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_ureqsxuser' => array(
			'hdr' => array('username', 'requests'),
			'sql' =>'SELECT username, COUNT(*) as requests FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY username ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_areqsxuser' => array(
			'hdr' => array('username', 'requests'),
			'sql' =>'SELECT username, COUNT(*) as requests FROM {db_prefix}wala_web_access_log GROUP BY username ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_ureqsxbrowser' => array(
			'hdr' => array('browser', 'requests'),
			'sql' =>'SELECT browser_ver, COUNT(*) as requests FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY browser_ver ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_areqsxbrowser' => array(
			'hdr' => array('browser', 'requests'),
			'sql' =>'SELECT browser_ver, COUNT(*) as requests FROM {db_prefix}wala_web_access_log GROUP BY browser_ver ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_uipsxcountry' => array(
			'hdr' => array('country', 'ips'),
			'sql' =>'SELECT country, COUNT(DISTINCT ip_packed) AS ips FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 GROUP BY country ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_aipsxcountry' => array(
			'hdr' => array('country', 'ips'),
			'sql' =>'SELECT country, COUNT(DISTINCT ip_packed) AS ips FROM {db_prefix}wala_web_access_log GROUP BY country ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_uipsxasn' => array(
			'hdr' => array('asn', 'asn name', 'ips'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(DISTINCT ip_packed) AS ips FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) WHERE status <> 403 AND status <> 429 GROUP BY a.asn ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_aipsxasn' => array(
			'hdr' => array('asn', 'asn name', 'ips'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(DISTINCT ip_packed) AS ips FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) GROUP BY a.asn ORDER BY ips DESC LIMIT 500',
		),
		'wala_rpt_ulikesxcountry' => array(
			'hdr' => array('country', 'view likes'),
			'sql' =>'SELECT country, COUNT(*) AS requests FROM {db_prefix}wala_web_access_log WHERE status <> 403 AND status <> 429 AND request LIKE \'action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY country ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_alikesxcountry' => array(
			'hdr' => array('country', 'view likes'),
			'sql' =>'SELECT country, COUNT(*) AS requests FROM {db_prefix}wala_web_access_log WHERE request LIKE \'%action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY country ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_ulikesxasn' => array(
			'hdr' => array('asn', 'asn name', 'view likes'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(*) AS requests FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) WHERE status <> 403 AND status <> 429 AND request LIKE \'%action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY a.asn ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_alikesxasn' => array(
			'hdr' => array('asn', 'asn name', 'view likes'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(*) AS requests FROM {db_prefix}wala_web_access_log wal INNER JOIN {db_prefix}wala_asns a ON (wal.asn = a.asn) WHERE request LIKE \'%action=likes%\' AND request LIKE \'%sa=view%\' GROUP BY a.asn ORDER BY requests DESC LIMIT 500',
		),
		'wala_rpt_userxasn' => array(
			'hdr' => array('asn', 'asn name', 'users'),
			'sql' =>'SELECT a.asn, a.asn_name, COUNT(*) as users FROM {db_prefix}wala_members m INNER JOIN {db_prefix}wala_asns a ON (m.asn = a.asn) GROUP BY a.asn, a.asn_name ORDER BY users DESC LIMIT 500',
		),
		'wala_rpt_userxcountry' => array(
			'hdr' => array('country', 'users'),
			'sql' => 'SELECT country, COUNT(*) as users FROM {db_prefix}wala_members GROUP BY country ORDER BY users DESC LIMIT 500',
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
 * WALA start response.
 * Used before loading dbip_asn, dbip_country & the access log.
 * Clear out temp files to start with an empty slate.
 *
 * Action: xmlhttp
 * Subaction: walastart
 *
 * @return null
 *
 */
function wala_start() {
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
		if (@mkdir($temp_dir, 0755) === false)
			$issues = true;
	}

	// If POST fails due to network settings issues, these aren't set...
	$file_name = '';
	if (isset($_POST['name']) && is_string($_POST['name']))
		$file_name = $_POST['name'];
	else
		$issues = true;

	$file_type = '';
	if (isset($_POST['file_type']) && is_string($_POST['file_type']))
		$file_type = $_POST['file_type'];
	else
		$issues = true;

	// Since this is the start of the whole process, clear out all similar filenames
	// in case anything left over from previous failed attempts - .csvs and .gzs, all parts#s.
	if (substr($file_name, -3) === '.gz')
		$del_pattern = substr($file_name, 0, -3);
	else
		$del_pattern = $file_name;

	$files = glob($temp_dir . '/' . $del_pattern . '*');
	foreach($files as $file){
		if(is_file($file)) {
			@unlink($file);
		}
	}

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
		if (@mkdir($temp_dir, 0755) === false)
			$issues = true;
	}

	// If POST fails due to network settings issues, these aren't set...
	$file_name = '';
	if (isset($_POST['name']) && is_string($_POST['name']))
		$file_name = $_POST['name'];
	else
		$issues = true;

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

	// Move the current chunk to tmp
	if (@move_uploaded_file($_FILES['chunk']['tmp_name'], $temp_dir . '/' . $file_name . '.chunk.' . $file_index) === false)
		$issues = true;

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

	// If file system or post issues encountered, return a 500
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

	// Build the gz file from the chunks...
	$file_path = $temp_dir . '/' . $file_name . '.chunk.*';
	$file_parts = glob($file_path);
	sort($file_parts, SORT_NATURAL);

	$final_file_name = $temp_dir . '/' . $file_name;
	$final_file = @fopen($final_file_name, 'w');
	if ($final_file === false)
		$issues = true;

	foreach ($file_parts as $file_part) {
		$fp_in = @fopen($file_part, 'rb');
		if ($fp_in === false) {
			$issues = true;
			continue;
		}
		if (@stream_copy_to_stream($fp_in, $final_file) === false) {
			$issues = true;
		}
		@fclose($fp_in);
		@unlink($file_part);
	}

	@fclose($final_file);

	if ($total_chunks != count($file_parts)) {
		// It's not usable...
		@unlink($final_file_name);
		$issues = true;
	}

	// Now that we have a readable .gz, break it up into .csvs
	static $commit_rec_count = 25000;
	$reccount = 0;
	$index = 1;

	// If gz filename ended in .gz, strip it for csv name...
	if (substr($file_name, -3) === '.gz')
		$filename_csv = substr($file_name, 0, -3);
	else
		$filename_csv = $file_name;

	if (!$issues) {
		$fpgz = @gzopen($temp_dir . '/' . $file_name, 'r');
		$fpcsv = @fopen($temp_dir . '/' . $filename_csv . '.chunk.' . $index, 'w');

		$buffer = @fgets($fpgz);
		while ($buffer !== false) {
			$reccount++;
			if ($reccount >= $commit_rec_count) {
				fclose($fpcsv);
				$reccount = 0;
				$index++;
				$fpcsv = @fopen($temp_dir . '/' . $filename_csv . '.chunk.' . $index, 'w');
			}
			@fwrite($fpcsv, $buffer);
			$buffer = @fgets($fpgz);
		}
		@fclose($fpcsv);
		@gzclose($fpgz);
		// Don't need this anymore...
		@unlink($final_file_name);
	}

	// Truncate target table...
	require_once($sourcedir . '/WALAnalyzerModel.php');
	if (!$issues) {
		if ($file_type === 'asn')
			truncate_dbip_asn();
		elseif ($file_type === 'country')
			truncate_dbip_country();
		elseif ($file_type === 'log')
			truncate_web_access_log();
	}

	// For a simple generic yes/no response
	$context['sub_template'] = 'generic_xml';

	if ($issues) {
		$context['xml_data'][] = array('value' => 'FAILURE');
		send_http_status(500);
	}
	else
		$context['xml_data'][] = array('value' => 'OK ' . $index . ' chunks');
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

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	// If file system or post issues encountered, return a 500
	$issues = false;

	// Gonna need this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

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

	$index = 0;
	if (isset($_POST['index']) && is_numeric($_POST['index']))
		$index = $_POST['index'];
	else
		$issues = true;

	$file_type = '';
	if (isset($_POST['file_type']) && is_string($_POST['file_type']))
		$file_type = $_POST['file_type'];
	else
		$issues = true;

	// If gz filename ended in .gz, strip it...
	if (substr($file_name, -3) === '.gz')
		$filename_csv = substr($file_name, 0, -3);
	else
		$filename_csv = $file_name;

	// Build the file from the info passed
	$filename_csv .= '.chunk.' . $index;


	// Now choose what to load based on file_type
	// Disable autocommits for mass inserts (can hide errors, though...)
	if (!$issues) {
		start_transaction();
		if ($file_type === 'asn')
			$issues = wala_load_asn($temp_dir . '/' . $filename_csv);
		elseif ($file_type === 'country')
			$issues = wala_load_country($temp_dir . '/' . $filename_csv);
		elseif ($file_type === 'log')
			$issues = wala_load_log($temp_dir . '/' . $filename_csv);

		// If issues found here, it's an invalid file format...
		// Logging error because we're not in a normal theme context...
		if ($issues) {
			loadLanguage('WALAnalyzer');
			log_error($txt['wala_file_error'], 'general', __FILE__, __LINE__);
		}
		commit();
	}

	// Don't need this one anymore either...
	@unlink($temp_dir . '/' . $filename_csv);

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
 * WALA end response.
 * Used after loading dbip_asn, dbip_country & the access log.
 * Update status upon successful completion.
 *
 * Action: xmlhttp
 * Subaction: walaend
 *
 * @return null
 *
 */
function wala_end() {
	global $context, $cachedir, $sourcedir;

	// You have to be able to moderate the forum to do this.
	isAllowedTo('admin_forum');

	// Make sure the right person is putzing...
	checkSession();

	// if file system or post issues encountered, return a 500
	$issues = false;

	// Gonna need this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

	// Let's use our own subdir...
	$temp_dir = $cachedir . '/wala';
	if (!is_dir($temp_dir)) {
		if (@mkdir($temp_dir, 0755) === false)
			$issues = true;
	}

	// If POST fails due to network settings issues, these aren't set...
	$file_name = '';
	if (isset($_POST['name']) && is_string($_POST['name']))
		$file_name = $_POST['name'];
	else
		$issues = true;

	$file_type = '';
	if (isset($_POST['file_type']) && is_string($_POST['file_type']))
		$file_type = $_POST['file_type'];
	else
		$issues = true;

	// Update the file status info...
	if (!$issues ) {
		start_transaction();
		if ($file_type === 'asn') {
			// Also load wala_asns from wala_dbip_asn...
			load_asn_names();
			update_status('asn', $file_name, time());
		}
		elseif ($file_type === 'country')
			update_status('country', $file_name, time());
		elseif ($file_type === 'log')
			update_status('log', $file_name, time());
		commit();
	}

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

	$file_name = '';
	if (isset($_POST['name']) && is_string($_POST['name']))
		$file_name = $_POST['name'];
	else
		$issues = true;

	// Gonna need this...
	require_once($sourcedir . '/WALAnalyzerModel.php');

	if (!$issues) {
    $gstart = microtime(true);
		// How many chunks total?  Not too big...
		// Even a small chunk of users, sorted by IP, can retrieve a large # of asn/country rows
		$reccount = count_web_access_log();
    var_dump(microtime(true) - $gstart);
		$commit_rec_count = ceil($reccount/20);
		if ($commit_rec_count > 5000)
			$commit_rec_count = 5000;
		$chunkct = ceil($reccount/$commit_rec_count);

		$offset = $index * $commit_rec_count;
		$limit = $commit_rec_count;
		$log = get_web_access_log($offset, $limit);
    var_dump(microtime(true) - $gstart);

		load_member_cache($log[0]['ip_packed'], end($log)['ip_packed']);
    var_dump(microtime(true) - $gstart);

		$min_ipv4 = $max_ipv4 = null;
		$min_ipv6 = $max_ipv6 = null;

		$count = count($log);

		// Min IPv4 always comes first
		if (strlen($log[0]['ip_packed']) === 4) {
			$min_ipv4 = $log[0]['ip_packed'];
		}

		// Find min/max IPv6 (backwards loop)
		for ($i = $count - 1; $i >= 0; $i--) {
			if (strlen($log[$i]['ip_packed']) === 16) {
				$min_ipv6 = $log[$i]['ip_packed'];

				// Max IP always last
				if ($max_ipv6 === null) {
					$max_ipv6 = $log[$i]['ip_packed'];
				}
			} else {
				// IPv4 ends here
				$max_ipv4 = $log[$i]['ip_packed'];
				break;
			}
		}

    var_dump(microtime(true) - $gstart);
		if ($min_ipv4 !== null) {
			$ipv4_asns = get_asns($min_ipv4, $max_ipv4);
		}

		if ($min_ipv6 !== null) {
			$ipv6_asns = get_asns($min_ipv6, $max_ipv6);
		}

		if ($min_ipv4 !== null) {
			$ipv4_countries = get_countries($min_ipv4, $max_ipv4);
		}

		if ($min_ipv6 !== null) {
			$ipv6_countries = get_countries($min_ipv6, $max_ipv6);
		}

    var_dump(microtime(true) - $gstart);

    // Initialize cumulative timers
$cumulative = [
    'asn'     => 0.0,
    'country' => 0.0,
    'username'=> 0.0,
    'update'  => 0.0,
];

foreach ($log as &$entry_info) {
    if (strlen($entry_info['ip_packed']) === 4) {
    $start = microtime(true);
		$entry_info['asn'] = binary_search_data($entry_info['ip_packed'], $ipv4_asns);
    $cumulative['asn'] += microtime(true) - $start;
    $start = microtime(true);
		$entry_info['country'] = binary_search_data($entry_info['ip_packed'], $ipv4_countries);
    $cumulative['country'] += microtime(true) - $start;
	} else {
    $start = microtime(true);
		$entry_info['asn'] = binary_search_data($entry_info['ip_packed'], $ipv6_asns);
    $cumulative['asn'] += microtime(true) - $start;
    $start = microtime(true);
		$entry_info['country'] = binary_search_data($entry_info['ip_packed'], $ipv6_countries);
    $cumulative['country'] += microtime(true) - $start;
	}

    // Username lookup
    $start = microtime(true);
    $entry_info['username'] = get_username($entry_info['ip_packed']);
    $cumulative['username'] += microtime(true) - $start;

    // DB update
}

		start_transaction();
    var_dump(microtime(true) - $gstart);
    $start = microtime(true);
    update_web_access_log($log);
    var_dump(microtime(true) - $gstart);
    var_dump(microtime(true) - $start);// Log cumulative times for the entire chunk
//~ var_dump($cumulative,$cumulativeupdate,$index);
		commit();
    var_dump(microtime(true) - $gstart);
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
 * WALA_load_asn - load a chunk of the dbip asn file to db.
 *
 * Action: na - helper function
 *
 * @param string filename of chunk
 *
 * @return bool issues found
 *
 */
function wala_load_asn($filename = '') {
	global $smcFunc;

	$fp = @fopen($filename, 'r');
	$buffer = @fgetcsv($fp, null, ",", "\"", "\\");
	$inserts = array();

	// $buffer[0] = ip from, display format
	// $buffer[1] = ip to, display format
	// $buffer[2] = asn
	// $buffer[3] = asn desc
	while ($buffer !== false) {
		// Uploaded from random sources????  Let's make sure we're good...
		if (!filter_var($buffer[0], FILTER_VALIDATE_IP) || !filter_var($buffer[1], FILTER_VALIDATE_IP) || !is_numeric($buffer[2]) || !is_string($buffer[3]))
			return true;

		// Note SMF deals with the inet_pton() for type inet, so just pass ip display format here...
		$inserts[] = array(
			$buffer[0],
			$buffer[1],
			$buffer[0],
			$buffer[1],
			$buffer[2],
			$smcFunc['htmlspecialchars']($buffer[3]),
		);
		$buffer = @fgetcsv($fp, null, ",", "\"", "\\");
	}
	insert_dbip_asn($inserts);
	@fclose($fp);
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
function wala_load_country($filename = '') {
	global $smcFunc;

	$batch_size = 1000;
	$fp = @fopen($filename, 'r');
	$buffer = @fgetcsv($fp, null, ",", "\"", "\\");
	$inserts = array();

	// $buffer[0] = ip from, display format
	// $buffer[1] = ip to, display format
	// $buffer[2] = two char country code
	$inserts = array();
	while ($buffer !== false) {
		// Uploaded from random sources????  Let's make sure we're good...
		if (!filter_var($buffer[0], FILTER_VALIDATE_IP) || !filter_var($buffer[1], FILTER_VALIDATE_IP) || !is_string($buffer[2]))
			return true;

		// Note SMF deals with the inet_pton() for type inet, so just pass ip display format here...
		$inserts[] = array(
			$buffer[0],
			$buffer[1],
			$buffer[0],
			$buffer[1],
			$smcFunc['htmlspecialchars']($buffer[2]),
		);
		if (count($inserts) >= $batch_size) {
			insert_dbip_country($inserts);
			$inserts = array();
		}
		$buffer = @fgetcsv($fp, null, ",", "\"", "\\");
	}
	if (!empty($inserts)) {
		insert_dbip_country($inserts);
	}
	@fclose($fp);
	return false;
}

/**
 * WALA_load_log - load a chunk of the web access log file to the db.
 *
 * Action: na - helper function
 *
 * @param string filename of chunk
 *
 * @return null
 *
 */
function wala_load_log($filename = '') {
	global $smcFunc, $cache_enable;

	$fp = @fopen($filename, 'r');
	if (!$fp) {
		return true;
	}

	$buffer = @fgetcsv($fp, null, " ", "\"", "\\");
	$inserts = array();

	// Static caches for repeated lookups
	static $req_cache = array();
	static $agent_cache = array();
	static $browser_cache = array();

	$batch_size = 100;
	$batch_count = 0;

	while ($buffer !== false) {
		// Uploaded from random sources????  Let's make sure we're good...
		// Check the IP...
		if (!filter_var($buffer[0], FILTER_VALIDATE_IP))
			return true;

		// Check the ints...
		if (!is_numeric($buffer[6]) || !is_numeric($buffer[7]))
			return true;

		// Check the date & time, ensure apache common log format
		$dt_string = substr($buffer[3] . $buffer[4], 1, -1);
		$ts = parseApacheDateTimeImmCached($dt_string);
		if ($ts === false)
			return true;

		// Check the strings...
		if (!is_string($buffer[1]) || !is_string($buffer[2]) || !is_string($buffer[5]) || !is_string($buffer[8]) || !is_string($buffer[9]))
			return true;


		$request = $buffer[5];
		$user_agent = $buffer[9];

		// Cached lookups
		if (!isset($req_cache[$request])) {
			$req_cache[$request] = get_request_type($request);
		}
		if (!isset($agent_cache[$user_agent])) {
			$agent_cache[$user_agent] = get_agent($user_agent);
		}
		if (!isset($browser_cache[$user_agent])) {
			$browser_cache[$user_agent] = get_browser_ver($user_agent);
		}

		$inserts[] = array(
			// The first fields are common when the apache standard logfile is used; ignore the others in the csv, as they vary a lot
			$buffer[0],									// ip packed
			$smcFunc['htmlspecialchars']($buffer[1]),	// client (usually unused)
			$smcFunc['htmlspecialchars']($buffer[2]),	// requestor (usually unused)
			substr($buffer[3], 1),						// date timestamp, strip the [
			substr($buffer[4], 0, -1),					// tz, strip the ]
			$smcFunc['htmlspecialchars']($buffer[5]),	// request
			(int) $buffer[6],							// status
			(int) $buffer[7],							// size
			$smcFunc['htmlspecialchars']($buffer[8]),	// referrer
			$smcFunc['htmlspecialchars']($buffer[9]),	// useragent
			// These fields are calc'd here...
			$buffer[0],									// ip display
			$req_cache[$request],                     // request type
			$agent_cache[$user_agent],                // agent
			$browser_cache[$user_agent],              // browser version
			$ts,										// dt in unix epoch format
		);

		$batch_count++;
		if ($batch_count >= $batch_size) {
			insert_log($inserts);
			$inserts = array();
			$batch_count = 0;
		}

		$buffer = fgetcsv($fp, null, " ", "\"", "\\");
	}

	// Flush remaining
	if (!empty($inserts)) {
		insert_log($inserts);
	}

	fclose($fp);

	return false;
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
 * Look up the country for a packed IP using binary search (raw bytes).
 *
 * @param string $ip_packed Packed binary IP (4 or 16 bytes)
 * @param bool   $timed     Optional; if true, prints lookup time
 * @return string Country code or empty string
 */
function binary_search_data($ip_packed, $data) {
	$low = 0;
	$high = count($data) - 1;
	$output = '';

	while ($low <= $high) {
		$mid = intdiv($low + $high, 2);
		$row = $data[$mid];

		if ($ip_packed > $row['ip_to_packed']) {
			$low = $mid + 1;
		} elseif ($ip_packed < $row['ip_from_packed']) {
			$high = $mid - 1;
		} else {
			$output = $row['output'];
			break;
		}
	}

	return $output;
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
