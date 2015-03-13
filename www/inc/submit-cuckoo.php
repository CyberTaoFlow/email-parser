<?php
	// connect to the database
	include 'db-connection.php';

	$hash = $_GET["md5"];
	$sql = "SELECT attachment_ref.name, attachment.payload AS data FROM attachment INNER JOIN attachment_ref ON attachment.id=attachment_ref.attachment_id WHERE attachment.md5='$hash'";

	$rs = $db->query($sql);
	if ($rs === false){
	  // Trigger an error, show the user what went wrong
	  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
	} else {
		$rs->data_seek(0);
		$file = $rs->fetch_assoc();
	}

	$finfo = new finfo(FILEINFO_MIME);
	$filetype = $finfo->buffer(zlib_decode($file['data']));
	$filesize = strlen(zlib_decode($file['data']));

	echo '<div class="modal-header">';
	echo '<button aria-hidden="true" data-dismiss="modal" class="close" type="button">&times;</button>';
	echo '<h4 class="modal-title">Submit File to Cuckoo Sandbox</h4>';
	echo '</div>';
	echo '<div class="modal-body">File Details:';
	echo '<pre>CHECKSUM: ', $hash, PHP_EOL;
	echo 'FILENAME: ', $file['name'], PHP_EOL;
	echo 'FILESIZE: ', $filesize, PHP_EOL;
	echo 'FILETYPE: ', $filetype, '</pre>';

	if(substr($filetype, 0, 4) === "text"){
		echo 'Sample of text:';
		echo '<pre>', substr(nl2br(zlib_decode($file['data'])), 0, 512), '</pre>';
	}

	// todo:
	// POST attachment to cuckoo API
	// visual feedback
	// update attachment set analyzed=1 when cuckoo returns URL from API

	echo '</div>';

?>
