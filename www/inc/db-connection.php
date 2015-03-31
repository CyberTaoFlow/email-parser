<?php
// the database server ip or hostname
$dbhost = "localhost";
// the user that has access to the database
$dbuser = "root";
// the password of the user
$dbpass = "";
// the database to work with
$dbname = "mail";

$db = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

if($db->connect_error){
  trigger_error('Unable to connect to database [' . $db->connect_error, E_USER_ERROR . ']');
}
?>
