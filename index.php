<?php
require_once 'nmap.cls.php';
$n=new WebMap('/usr/local/bin/nmap');
$n->run_nmap();

?>