# Native PHP after the CloudLinux conversion

The conversion removes the Standard edition's PHP (Remi, PHP-FPM), which owned
`/usr/bin/php`, `/usr/bin/php-cgi` and `/etc/php.ini`. CloudLinux's PHP Selector
still needs all three as its "native" version: `cagefsctl --setup-cl-selector`
and `selectorctl --apply-global-php-ini` fail with
`Error: failed to open file /etc/php.ini` / `... path: /usr/bin/php-cgi` without them.

The upgrade makes native PHP the server default, alt-php 8.4, as real files
(mod_lsapi and CageFS do not accept symlinks for these):

    install -m 0755 /opt/alt/php84/usr/bin/php     /usr/bin/php
    install -m 0755 /opt/alt/php84/usr/bin/php-cgi /usr/bin/php-cgi
    install -m 0644 /opt/alt/php84/etc/php.ini     /etc/php.ini
    cagefsctl --setup-cl-selector
    selectorctl --apply-global-php-ini

They are copies, so an alt-php84 update does not reach them: the upgrade's
post-update step repeats the three installs.
