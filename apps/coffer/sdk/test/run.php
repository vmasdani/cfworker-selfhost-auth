<?php
// Test runner for Coffer.php; see scripts/sdk-matrix.ts.
declare(strict_types=1);
require_once __DIR__ . '/Coffer.php';

$lang = $argv[1];
$c = Coffer::fromEnv();
$version = $c->writeSecret("FROM_{$lang}", "hello from {$lang} ünï ✓ \"q\"\n<&>");
$got = $c->getSecret("FROM_{$lang}");
$missing = $c->getSecret('NOPE_MISSING');
$c->writeSecret("TMP_{$lang}", 'x');
$d1 = $c->deleteSecret("TMP_{$lang}");
$d2 = $c->deleteSecret("TMP_{$lang}");
echo json_encode(['version' => $version, 'got' => $got, 'missingFound' => $missing !== null, 'deletedOnce' => $d1, 'deletedTwice' => $d2, 'all' => (object) $c->listAllSecrets()], JSON_UNESCAPED_UNICODE), "\n";
