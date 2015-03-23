<?php
include 'db-connection.php';

$sql = "SELECT email.timestamp AS timestamp, country, INET_NTOA(email.ip_src) as srcip, email.sender AS sender, email.subject AS subject, attachment_ref.name AS attachment, attachment.suspicion AS suspicion, attachment.md5 AS md5, count FROM email INNER JOIN attachment_ref ON attachment_ref.email_id=email.id INNER JOIN attachment ON attachment_ref.attachment_id=attachment.id ORDER BY timestamp DESC";
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  // we need an array this time
  $headers = array();
  // $tabled = array();
  // iterate through results
  while($row = $rs->fetch_array(MYSQLI_ASSOC)){
    $headers = array_keys($row);
    // $tabled[] = $row;
  }
  $rs->free();
}

?>
