<?php
$uploaddir = '/tmp/';
$uploadfile = $uploaddir . basename($_FILES['file']['name']);

if(move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
	echo "File Upload Successful", PHP_EOL;
	shell_exec('email-parser -p' . $uploadfile);
} else {
	echo "Upload unsuccessful", PHP_EOL;
	echo "Debug:", PHP_EOL;
	print_r($_FILES);
}
?>
