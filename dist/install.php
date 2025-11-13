<?php

global $smcFunc;

if (!isset($smcFunc['db_create_table']))
	db_extend('packages');

$create_tables = array(
	'wala_asns' => array(
		'columns' => array(
			array(
				'name' => 'asn',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'asn_name',
				'type' => 'tinytext',
				'not_null' => true,
			),
		),
		'indexes' => array(
			array(
				'type' => 'primary',
				'columns' => array('asn'),
			),
		),
	),
	'wala_status' => array(
		'columns' => array(
			array(
				'name' => 'file_type',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'file_name',
				'type' => 'tinytext',
				'not_null' => true,
			),
			array(
				'name' => 'last_proc_time',
				'type' => 'int',
				'default' => 0,
				'not_null' => true,
			),
		),
		'indexes' => array(
			array(
				'type' => 'primary',
				'columns' => array('file_type'),
			),
		),
	),
	'wala_members' => array(
		'columns' => array(
			array(
				'name' => 'ip_packed',
				'type' => 'inet',
				'not_null' => true,
			),
			array(
				'name' => 'id_member',
				'type' => 'mediumint',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'real_name',
				'type' => 'varchar',
				'size' => 255,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'is_activated',
				'type' => 'tinyint',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'posts',
				'type' => 'mediumint',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'total_time_logged_in',
				'type' => 'int',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'date_registered',
				'type' => 'int',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'last_login',
				'type' => 'int',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'asn',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'country',
				'type' => 'varchar',
				'size' => 2,
				'default' => '',
				'not_null' => true,
			),
		),
		'indexes' => array(
			array(
				'type' => 'primary',
				'columns' => array('id_member'),
			),
			array(
				'type' => 'index',
				'columns' => array('ip_packed'),
			),
			array(
				'type' => 'index',
				'columns' => array('asn'),
			),
		),
	),
	'wala_web_access_log' => array(
		'columns' => array(
			array(
				'name' => 'id_entry',
				'type' => 'int',
				'not_null' => true,
				'auto' => true,
			),
			array(
				'name' => 'ip_packed',
				'type' => 'inet',
				'not_null' => true,
			),
			array(
				'name' => 'client',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'requestor',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'raw_datetime',
				'type' => 'varchar',
				'size' => 32,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'raw_tz',
				'type' => 'varchar',
				'size' => 6,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'request',
				'type' => 'tinytext',
				'not_null' => true,
			),
			array(
				'name' => 'status',
				'type' => 'int',
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'size',
				'type' => 'int',
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'referrer',
				'type' => 'tinytext',
				'not_null' => true,
			),
			array(
				'name' => 'useragent',
				'type' => 'tinytext',
				'not_null' => true,
			),
			array(
				'name' => 'ip_disp',
				'type' => 'varchar',
				'size' => 42,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'request_type',
				'type' => 'varchar',
				'size' => 15,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'agent',
				'type' => 'varchar',
				'size' => 25,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'browser_ver',
				'type' => 'varchar',
				'size' => 25,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'datetime',
				'type' => 'int',
				'unsigned' => true,
				'default' => 0,
				'not_null' => true,
			),
			array(
				'name' => 'asn',
				'type' => 'varchar',
				'size' => 10,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'country',
				'type' => 'varchar',
				'size' => 2,
				'default' => '',
				'not_null' => true,
			),
			array(
				'name' => 'username',
				'type' => 'varchar',
				'size' => 50,
				'default' => '',
				'not_null' => true,
			),
		),
		'indexes' => array(
			array(
				'type' => 'primary',
				'columns' => array('id_entry'),
			),
			array(
				'type' => 'index',
				'columns' => array('ip_packed'),
			),
			array(
				'type' => 'index',
				'columns' => array('asn'),
			),
		),
	),
);

foreach ($create_tables AS $table_name => $data)
	$smcFunc['db_create_table']('{db_prefix}' . $table_name, $data['columns'], $data['indexes']);

// Init the upload tables...
$smcFunc['db_insert']('ignore',
	'{db_prefix}wala_status',
	array('file_type' => 'string-10', 'file_name' => 'string-255'),
	array(array('asn', ''), array('country', ''), array('member', ''), array('log', '')),
	array('file_type'),
);
