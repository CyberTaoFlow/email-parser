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
	$filetype = $finfo->buffer(gzuncompress($file['data']));
	$filesize = strlen(gzuncompress($file['data']));

        $url = 'http://cuckoo/tasks/create/file';

	$fdata = gzuncompress($file['data']);
	
	$curl_post_data = array(
		'file' => ';filename="'.$file['name'].'"'.$fdata,
		'tags' => 'email-parser, suspicious email'
	);
	
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_FAILONERROR, true);
	curl_setopt($ch, CURLOPT_URL, $url);
	curl_setopt($ch, CURLOPT_USERAGENT, "email-parser cURL PHP");
	curl_setopt($ch, CURLOPT_PORT, 1337);
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $curl_post_data);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	$result = curl_exec($ch);
	curl_close($ch);
		

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
		echo '<pre>', substr(nl2br(gzuncompress($file['data'])), 0, 512), '</pre>';
	}
	
	echo '<pre>test: ', $result, '</pre>';
	
	// todo:
	// POST attachment to cuckoo API
	// visual feedback
	// update attachment set analyzed=1 when cuckoo returns URL from API

	echo '</div>';

?>
