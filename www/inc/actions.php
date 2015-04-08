<?php

// connect to database
include 'db-connection.php';

// initialize arrays
$errors         = array();      // array to hold validation errors
$data           = array();      // array to pass back data

// retention
if (isset($_GET['retain'])){
  // escape for possible SQL injection
  $retention_id = $db->real_escape_string($_GET['retain']);
  $sql = "UPDATE attachment SET retention = 1 WHERE id = '$retention_id'";
  $result = $db->query($sql);
  if ($result === false){
    // trigger an error, show the user what went wrong
    $errors['retention'] = 'Something went wrong with the database';
    trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
  } else {
    $data['success'] = true;
    $data['message'] = "Attachment retained";
  }
}

// delete email
if (isset($_GET['delete'])){
  //escape for SQLi
  $delete_id = $db->real_escape_string($_GET['delete']);
  $sql = "DELETE FROM email WHERE id = '$delete_id' INNER JOIN ref ON email.eid=ref.email_id"
  $result = $db->query($sql);
  if ($result === false){
    // error out
    $errors['delete'] = 'Something went wrong with the database';
    trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
  } else {
    $data['success'] = true;
    $data['message'] = "Email Deleted";
  }
}

// mark as analyzed
if (isset($_GET['analyze'])){
  // escape for possible SQL injection
  $analyze_id = $db->real_escape_string($_GET['analyze']);
  $sql = "UPDATE attachment SET analyzed = 1 WHERE id = '$analyze_id'";
  $result = $db->query($sql);
  if ($result === false){
    // trigger errors
    $errors['analyze'] = 'Something went wrong with the database';
    trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
  } else {
    $data['success'] = true;
    $data['message'] = "Attachment analyzed";
  }
}



// if there are errors, return errors to the array
if ( ! empty($errors)) {
  $data['success'] = false;
  $data['errors']  = $errors;
}

// return json to the form
echo json_encode($data);
