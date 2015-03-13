<?php
function get_country_by_ip($ip){
  $str_geoiplookup = "geoiplookup " . $ip . "| cut -f4 -d' ' | tr -d ','";
  $str_country = shell_exec($str_geoiplookup);
  $country = strtolower($str_country);
  return $country;
}
?>
