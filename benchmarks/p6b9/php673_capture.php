<?php
declare(strict_types=1);
/**
 * B9 fixed upstream PHP SDK serialization experiment.
 * Arguments: /path/to/source-checkout /path/to/result.json
 * Only synthetic values, no network, no SDK source changes.
 */
if ($argc !== 3) { fwrite(STDERR, "Usage: php capture.php SDK_ROOT OUTPUT\n"); exit(2); }
$root = realpath($argv[1]);
if ($root === false || !is_file($root.'/src/Schema/Result/CallToolResult.php')) {
    throw new RuntimeException('Not a pinned PHP SDK checkout');
}
spl_autoload_register(static function(string $name) use ($root): void {
    if (!str_starts_with($name, 'Mcp\\')) return;
    $path = $root.'/src/'.str_replace('\\', '/', substr($name, 4)).'.php';
    if (is_file($path)) require_once $path;
});
use Mcp\Schema\Content\TextContent;
use Mcp\Schema\Result\CallToolResult;
$text = [new TextContent('synthetic')];
$cases = [
    'explicit_null' => new CallToolResult($text, structuredContent: null),
    'omitted' => CallToolResult::success($text),
    'explicit_false' => new CallToolResult($text, structuredContent: false),
    'explicit_zero' => new CallToolResult($text, structuredContent: 0),
    'explicit_empty' => new CallToolResult($text, structuredContent: ''),
    'from_array_null' => CallToolResult::fromArray([
        'content'=>[['type'=>'text','text'=>'synthetic']], 'structuredContent'=>null
    ]),
];
$results = [];
foreach ($cases as $id => $value) {
    $results[$id] = json_decode(json_encode($value, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
}
file_put_contents($argv[2], json_encode([
    'schema'=>'p6b9-php673-actual-upstream-serializer-v1',
    'component'=>'Mcp\\Schema\\Result\\CallToolResult',
    'origin'=>'ACTUAL_PHP_SDK_SERIALIZED_OBJECT',
    'cases'=>$results,
], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
