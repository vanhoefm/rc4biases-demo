<?php

$rawheaders = $_SERVER['REQUEST_HEADERS'];
echo "<pre>$rawheaders</pre>";

$directory = "/usr/share/nginx/rc4https/www/headers/";
$time      = $date = date('Y_m_d__h_i_s') . "__" . rand() . ".bin";
$file      = $directory . $time;
echo "<p>Dumping headers to $file</p>";

file_put_contents($file, $rawheaders);

?>
