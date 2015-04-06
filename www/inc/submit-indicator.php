<?php

include 'db-connection.php';

// initialize arrays
$errors         = array();      // array to hold validation errors
$data           = array();      // array to pass back data

// variable validation
if (empty($_POST['type'])){
  $errors['type'] = 'Indicator type required';
}

if (empty($_POST['indicator'])){
  $errors['indicator'] = 'Indicator required';
}

if (empty($_POST['expiry'])){
  $errors['expiry'] = 'Expiry date required';
}
// if there are errors, return errors to the array
if ( ! empty($errors)) {
  $data['success'] = false;
  $data['errors']  = $errors;
} else {
  // do SQL things
  $post_type = $db->real_escape_string($_POST['type']);
  $post_indicator = $db->real_escape_string($_POST['indicator']);
  $post_expires = $db->real_escape_string($_POST['expiry']);
  $sql = "INSERT IGNORE INTO target (expires, type, target) VALUES ('$post_expires','$post_type','$post_indicator')";
  $rs = $db->query($sql);
  if ($rs === false){
    // Trigger an error, show the user what went wrong
    trigger_error('Wrong SQL:' . $sql . ' Error: ' . $db->error, E_USER_ERROR);
    } else {
      $data['success'] = true;
      $data['message'] = "Row inserted";
    }
}

// return json to the form
echo json_encode($data);
