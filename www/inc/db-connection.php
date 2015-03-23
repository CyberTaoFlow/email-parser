<?php
// the database server ip or hostname
$dbhost = "funbox.pulsifer.ca";
// the user that has access to the database
$dbuser = "emailparse";
// the password of the user
$dbpass = "pythonpassword";
// the database to work with
$dbname = "email";

$db = new mysqli($dbhost, $dbuser, $dbpass, $dbname);

if($db->connect_error){
  trigger_error('Unable to connect to database [' . $db->connect_error, E_USER_ERROR . ']');
}
?>
