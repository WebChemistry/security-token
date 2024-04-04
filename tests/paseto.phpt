<?php declare(strict_types = 1);

use Tester\Assert;
use WebChemistry\SecurityToken\Key\Base64SecurityKey;
use WebChemistry\SecurityToken\Token\PasetoTokenSerializer;

require __DIR__ . '/bootstrap.php';

$key = new Base64SecurityKey('+DlgMCffUMgWdfaeqOp4Ipp6+p6dQMcNMjelqvbz+VQ=');
$serializer = new PasetoTokenSerializer($key, 'test');

Assert::match('#^v4\.local\.[\w-]+$#', $serializer->serialize(['user' => 1]));

$claims = $serializer->unserialize($serializer->serialize(['user' => 1]), 'test');

Assert::notNull($claims);
Assert::same(1, $claims->get('user'));

Assert::null($serializer->unserialize($serializer->serialize(['user' => 1]), 'unknown'));
Assert::null($serializer->unserialize($serializer->serialize(['user' => 1], '- 1 second')));
Assert::null($serializer->unserialize($serializer->serialize(['user' => 1], notBefore: '+ 1 second')));
