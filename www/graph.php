<?php 
    $data = array(array('1999',3.0),array('2000',3.9),array('2001',2.0),array('2002',1.2));
    $array = array('label' => 'Scores','data'=>$data);
    echo json_encode(array($array));
?>
