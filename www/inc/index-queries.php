<?php

// this php file is what drives the graphs on the front page

// the first query will be well documented
// the second query will not be as verbose
// the third+ query will not contain any comments

include 'db-connection.php';

// SQL query that retrieves total email count (total_emails), unique IP addresses (uniq_ips), and has a subquery to count total_attachments
$sql = 'SELECT COUNT(*) as total_emails, COUNT(distinct email.ip_src) as uniq_ips, (SELECT COUNT(*) FROM attachment) as total_attachments FROM email';
// Submit the query to the database, store results in variable $rs
$rs = $db->query($sql);
// If something wrong happened with getting the results
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  // The data_seek function starts looking (seeking) at an arbitrary row in a result set
  // in this case, we start looking at 0
  $rs->data_seek(0);
  // This while loop iterates over the returned rows
  // fetch_assoc returns a row as an associative array (fetches a row with names)
  while($row = $rs->fetch_assoc()){
    // sets variable totalemails to the value returned from the database
    $totalemails = $row['total_emails'];
    // sets variable uniqips to the value returned from the database
    $uniqips = $row['uniq_ips'];
    // sets variable totalattachments to the value returned from the database
    $totalattachments = $row['total_attachments'];
  }
  // this frees up the memory used up by the results
  // this will lessen load on the server since there are a lot of queries
  $rs->free();
}

// SQL query returns the total suspicious attachments
$sql = 'SELECT COUNT(*) AS suspicious_attachments FROM attachment WHERE suspicion > 0';
// Submit the query to db
$rs = $db->query($sql);
// If something broke
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  // Start at 0
  $rs->data_seek(0);
  // We know we're only getting one row
  // no need for an iterative loop
  $row = $rs->fetch_assoc();
  // set the variable with the result
  $attachmentcount = $row['suspicious_attachments'];
  // free memory
  $rs->free();
}

// SQL Query to determine the attachment with the highest suspicion
$sql = 'SELECT attachment_ref.name AS mostbad, attachment.suspicion AS highestsuspicion, attachment.md5 AS mostbadmd5 FROM attachment INNER JOIN attachment_ref ON attachment_ref.attachment_id=attachment.id WHERE attachment.analyzed=0 ORDER BY suspicion DESC LIMIT 1';
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  $row = $rs->fetch_assoc();
  // setting variables from results
  $attachmentmostsuspicious = $row['mostbad'];
  $attachmentmostsuspiciousmd5 = $row['mostbadmd5'];
  $highestsuspicion = $row['highestsuspicion'];
  // free memory
  $rs->free();
}

// SQL query to determine number of analyzed attachments
$sql = 'SELECT COUNT(*) AS count FROM attachment WHERE analyzed=1';
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  $row = $rs->fetch_assoc();
  $totalanalyzed = $row['count'];
  $rs->free();
}

// SQL query to determine the size of the database
$sql = "SELECT Round(Sum(data_length + index_length) / 1024 / 1024, 1) AS size FROM information_schema.tables WHERE table_schema='email'";
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  $row = $rs->fetch_assoc();
  $dbsize = $row['size'];
  $rs->free();
}

// SQL query to determine the last db input
$sql = 'SELECT timestamp FROM email ORDER BY timestamp DESC LIMIT 1';
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  $row = $rs->fetch_assoc();
  $lastinput = $row['timestamp'];
}

// SQL query for top 10 domains
$sql = "SELECT COUNT(substring_index(sender, '@', -1)) as count,SUBSTRING_INDEX(sender, '@', -1) AS domain FROM email GROUP BY sender ORDER BY count DESC LIMIT 10";
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  // we need an array this time
  $domains = array();
  // iterate through results
  while($row = $rs->fetch_array(MYSQLI_ASSOC)){
    $domains[] = $row;
  }
  $rs->free();
}

// SQL query for the most targeted email
$sql = "SELECT recipient FROM email_recipients GROUP BY recipient ORDER BY COUNT(recipient) DESC LIMIT 1";
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  $row = $rs->fetch_assoc();
  $most_targeted = $row['recipient'];
  $rs->free();
}

// SQL query for the above's attachments
$sql = "SELECT attachment_ref.name, attachment.md5 FROM email_recipients RIGHT JOIN attachment_ref ON email_recipients.email_id=attachment_ref.email_id INNER JOIN attachment ON attachment_ref.attachment_id=attachment.id WHERE recipient = '" . $most_targeted . "' ORDER BY name";
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  // we need an array this time
  $attachments = array();
  while($row = $rs->fetch_array(MYSQLI_ASSOC)){
    $attachments[] = $row;
  }
  $rs->free();
}

// SQL query for email by hour
if(! empty($_GET['graph'])){
  switch($_GET['graph'])
  {
    case 'hourly':
      $graphtime = "Last 24 Hours";
      $sql = "SELECT hour(timestamp) AS time, COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL 1 DAY) GROUP BY hour(timestamp)";
      break;
    case 'daily':
      $graphtime = "Last 30 Days";
      $sql = "SELECT day(timestamp) AS time, COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL 30 DAY) GROUP BY day(timestamp)";
      break;
    case 'weekly':
      $graphtime = "Last 8 Weeks";
      $sql = "SELECT week(timestamp) AS time, COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL 8 WEEK) GROUP BY week(timestamp)";
      break;
    case 'monthly':
      $graphtime = "Last 12 Months";
      $sql = "SELECT month(timestamp) AS time, COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL 12 MONTH) GROUP BY month(timestamp)";
      break;
    default:
      $graphtime = "Last 24 Hours";
      $sql = "SELECT hour(timestamp) AS time, COUNT(*) AS count FROM email WHERE timestamp > DATE_SUB(now(), INTERVAL 1 DAY) GROUP BY hour(timestamp)";
  }
}
$rs = $db->query($sql);
if ($rs === false){
  // Trigger an error, show the user what went wrong
  trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
} else {
  $rs->data_seek(0);
  // we need an array this time
  $time_graph = array();
  while($row = $rs->fetch_array(MYSQLI_ASSOC)){
    $time_graph[] = $row;
  }
  $rs->free();
}

$db->close();

?>
