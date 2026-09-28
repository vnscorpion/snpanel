<?php
// version|sapi|uid of the process that ran this|name of that uid
$f = __DIR__ . '/.snpuid' . getmypid();
@touch($f);
$u = @fileowner($f);
@unlink($f);
$name = '-';
if ($u !== false && function_exists('posix_getpwuid')) {
    $name = posix_getpwuid($u)['name'];
}
echo PHP_VERSION, '|', php_sapi_name(), '|', $u === false ? '-' : $u, '|', $name, "\n";
