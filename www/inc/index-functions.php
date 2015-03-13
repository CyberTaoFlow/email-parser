<?php
// this include contains the basic functions that drive the front page

function get_server_memory_usage(){
  // executes a shell command
  $free = shell_exec('free');
  // trims the string
  $free = (string)trim($free);
  // breaks the string up into an array
  $free_arr = explode("\n", $free);
  // breaks it up further
  $mem = explode(" ", $free_arr[1]);
  $mem = array_filter($mem);
  $mem = array_merge($mem);
  // maths!
  $memory_usage = $mem[2]/$mem[1]*100;

  return $memory_usage;
}

function get_disk_usage($d){
  $free = disk_free_space($d);
  $space = disk_total_space($d);
  $disk_usage = $free/$space*100;
  return $disk_usage;
}

function get_progress_bar_style($n) {
  if($n > 90) {return "progress-bar-danger"; }
  elseif($n > 70) {return "progress-bar-warning"; }
  else {return "progress-bar-success"; }
}

function get_server_cpu_usage(){
  $load = sys_getloadavg();
  return $load[0];
}

?>
