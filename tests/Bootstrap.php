<?php

$privateKey = __DIR__ . '/Stubs/private.key';

// Git does not preserve owner/group read permissions. Ensure the private-key
// fixture has the permissions required by league/oauth2-server on every clone.
if (file_exists($privateKey) && !chmod($privateKey, 0600)) {
    throw new RuntimeException(sprintf('Unable to secure private key fixture "%s".', $privateKey));
}

if (!@include_once __DIR__ . '/../vendor/autoload.php') {
    $message = <<<MSG
You must set up the project dependencies, run the following commands:
> wget http://getcomposer.org/composer.phar
> php composer.phar install
MSG;

    exit($message);
}
