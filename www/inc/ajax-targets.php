<?php

/*
 * DataTables example server-side processing script.
 *
 * Please note that this script is intentionally extremely simply to show how
 * server-side processing can be implemented, and probably shouldn't be used as
 * the basis for a large complex system. It is suitable for simple use cases as
 * for learning.
 *
 * See http://datatables.net/usage/server-side for full details on the server-
 * side processing requirements of DataTables.
 *
 * @license MIT - http://datatables.net/license_mit
 */

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * Easy set variables
 */

// DB table to use
$table = 'email';

// Table's primary key
$primaryKey = 'eid';

// Array of database columns which should be read and sent back to DataTables.
// The `db` parameter represents the column name in the database, while the `dt`
// parameter represents the DataTables column identifier. In this case simple
// indexes
$columns = array(
    array(
       'db' => 'eid',
       'dt' => 'DT_RowId',
       'formatter' => function( $d, $row ) {
           // Technically a DOM id cannot start with an integer, so we prefix
           // a string. This can also be useful if you have multiple tables
           // to ensure that the id is unique with a different prefix
           return 'row_'.$d;
           }
    ),
    array( 'db' => 'timestamp',         'dt' => 'timestamp' ),
    array( 'db' => 'country',           'dt' => 'country' ),
    array( 'db' => 'INET_NTOA(ip_src)', 'dt' => 'ip_src' ),
    array( 'db' => 'tcp_sport',         'dt' => 'tcp_sport' ),
    array( 'db' => 'sender',            'dt' => 'sender' ),
    array( 'db' => 'recipient',         'dt' => 'recipient' ),
    array( 'db' => 'subject',           'dt' => 'subject' ),
    array( 'db' => 'name',              'dt' => 'name' ),
    array( 'db' => 'suspicion',         'dt' => 'suspicion' ),
    array( 'db' => 'md5',               'dt' => 'md5' ),
    array( 'db' => 'count',             'dt' => 'count' ),
    array( 'db' => 'ssdeep',            'dt' => 'ssdeep' ),
    array( 'db' => 'message_body',      'dt' => 'message_body' )
);

$limit = "GROUP BY md5";

// SQL server connection information
$sql_details = array(
    'user' => 'root',
    'pass' => '',
    'db'   => 'mail',
    'host' => 'localhost'
);


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * If you just want to use the basic configuration for DataTables with PHP
 * server-side, there is no need to edit below this line.
 */

require( 'ssp.class-targets.php' );

echo json_encode(
    SSP::simple( $_GET, $sql_details, $table, $primaryKey, $columns )
);
