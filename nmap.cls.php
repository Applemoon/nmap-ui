<?php

ini_set("date.timezone", "America/New_York");

class WebMap {
  private $args='';
  function __construct($cmd)  {
    if (is_file($cmd) && is_executable($cmd)) {
      $this->nmapcmd=$cmd;
    } else {
      echo "nMap не найден!";
      exit();
    }
    $check="checked='CHECKED'";
    $this->title='nMap сканер';
    $this->dtstamp=date('YmdHms');
    if (is_array($_POST) && count($_POST) > 0) {
      foreach($_POST as $k => $v) {
        $this->$k=$v;
      }
    } elseif (is_array($_GET) && count($_GET) > 0) {
      foreach($_GET as $k => $v) {
        $this->$k=$v;
      }
    } else {
      $this->host='127.0.0.1';
      $this->connect=$check;
      $this->tcp=$check;
      $this->method='post';
    }

  if ($this->submit && $this->host)
  {
   $args = '';
   switch ($this->scan_type) 
   {
    case 'connect': $args .= '-sT '; $this->connect=$check; break;
    case 'syn':     $args .= '-sS '; $this->syn=$check;     break;
    case 'null':    $args .= '-sN '; $this->null=$check;    break;
    case 'fin';     $args .= '-sF '; $this->fin=$check;     break;
    case 'xmas':    $args .= '-sX '; $this->xmas=$check;    break;
    case 'ack':     $args .= '-sA '; $this->ack=$check;     break;
    case 'window':  $args .= '-sW '; $this->window=$check;  break;
    case 'ping';    $args .= '-sP '; $this->ping=$check;    break;
    default:
        $args.='-sT';
        $this->connect=$check;
   }
  
   switch ($this->ping_type) 
   {
    case 'tcp':      $args .= '-PT '; $this->tcp=$check;      break;
    case 'tcp_icmp': $args .= '-PB '; $this->tcp_icmp=$check;  break;
    case 'icmp':     $args .= '-PI '; $this->icmp=$check;     break;
    case 'none':     $args .= '-P0 '; $this->none=$check;     break;
    default:
        $args .= '-PB ';
        $this->tcp_icmp=$check;
   }
   if ($this->os_detect)     { 
       $args .= '-O '; 
       $this->os_detect=$check; 
   }
   if ($this->ident_info)    { 
       $args .= '-I '; 
       $this->ident_info=$check;     
   }
   if ($this->fragmentation) { 
       $args .= '-f '; 
       $this->fragmentation=$check;
   }
   if ($this->verbose)       { 
       $args .= '-v '; 
       $this->verbose=$check; 
   }
   if ($this->use_port)      { 
       $args .= '-p '.escapeshellarg($this->port_range);
       $this->use_port=$check; 
   }
   if ($this->fast_scan)     { 
       $args .= '-F '; 
       $this->fast_scan=$check;
   }
   if ($this->use_decoy)     { 
       $args .= '-D '.escapeshellarg($this->decoy_name); 
       $this->use_decoy=$check;
   }
   if ($this->use_device)    { 
       $args .= '-e '.escapeshellarg($this->device_name); 
       $this->use_device=$check;
   }
   if ($this->dont_resolve)  { 
       $args .= '-n '; 
       $this->dont_resolve=$check; 
   }
   if ($this->udp_scan)      { 
       $args .= '-sU ';
       $this->udp_scan=$check; 
   }
   if ($this->rpc_scan)      { 
       $args .= '-sR ';
       $this->rpc_scan=$check; 
   }
   $this->args=$args .= $this->host_flags.' '.escapeshellarg($this->host);
   return TRUE;
  } else { return FALSE; }
 }
 
 // nMap options
 private $nmap=array();
 /**
  * __get value from nmap array
  * @param type $name
  * @return boolean 
  */
 function __get($name) {
     if(array_key_exists($name, $this->nmap)) {
         return $this->nmap[$name];
     } else {
         return;
     }
 }
 /**
  * __set nmap value to array
  * @param type $name
  * @param type $value 
  */
 function __set($name, $value) {
     $this->nmap[$name]=$value;
 }

 /**
  * run nMap
  * @param bool $log Logging off by default since windows mostlikely won't have the tee command
  */
 function run_nmap($log=FALSE) {
    if ($this->submit && $this->host) {
       echo '<p id="nmap_cmd">'.$this->nmapcmd.' '.$this->args.'</p>';
       echo '<pre id="nmap_scan">';
       if ($log) {
        system($this->nmapcmd.' '.$this->args.' 2>&1 | tee nmap.'.$this->dtstamp.'.log' );
       } else {
        system($this->nmapcmd.' '.$this->args.' 2>&1' );
       }
       echo '</pre>';
    }
 }
 /**
  * xHTML Form for nMap front end
  * @return string
  */


}
?>