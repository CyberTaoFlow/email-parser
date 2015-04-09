<?php
// connect to the database
include 'db-connection.php';

function isValidMD5($md5 =''){
    return preg_match('/^[a-f0-9]{32}$/', $md5);
}

if(isValidMD5($_GET["md5"])){
	$hash = $_GET["md5"];
} else {
	die("Not a valid MD5");
}

$sql = "SELECT ref.name, attachment.payload AS data FROM attachment INNER JOIN ref ON ref.attachment_id=attachment.id WHERE attachment.md5='$hash'";

$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  // we need an array this time
  $file = array();
  // store results in a literal array
  $file = $rs->fetch_array(MYSQLI_ASSOC);
	// Create a File Info object
	$finfo = new finfo(FILEINFO_MIME);
	// Enumerate MIME type from buffer
	$filetype = $finfo->buffer(gzuncompress($file['data']));
	// Enumerate file size
	$filesize = strlen(gzuncompress($file['data']));
	// Return values to the browser
	header("Content-Type: {$filetype}");
	header("Content-Disposition: attachment; filename=\"{$file['name']}\"");
	header("Content-Length:{$filesize}");
	echo gzuncompress($file['data']);
	$rs->free();
}
?>
