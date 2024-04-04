<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Bridge\Nette;

use InvalidArgumentException;
use Nette\DI\CompilerExtension;
use Nette\DI\Definitions\Statement;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use stdClass;
use WebChemistry\SecurityToken\Key\Base64SecurityKey;
use WebChemistry\SecurityToken\Token\PasetoTokenSerializer;
use WebChemistry\SecurityToken\Token\TokenSerializerProvider;

final class SecurityTokenExtension extends CompilerExtension
{

	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'providers' => Expect::arrayOf(Expect::structure([
				'key' => Expect::string()->required(),
				'type' => Expect::string()->required(),
				'issuer' => Expect::string()->nullable(),
			]), Expect::string()),
		]);
	}

	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();
		/** @var stdClass $config */
		$config = $this->getConfig();

		$providers = [];

		foreach ($config->providers as $name => $struct) {
			if ($struct['type'] === 'paseto') {
				$providers[$name] = new Statement(PasetoTokenSerializer::class, [
					new Base64SecurityKey($struct['key']),
					$struct['issuer'] ?? null,
				]);

				if ($name === 'default') {
					$builder->addDefinition($this->prefix('tokenSerializer'))
						->setFactory($providers[$name]);
				}

			} else {
				throw new InvalidArgumentException(sprintf('Unknown token serializer type "%s"', $struct['type']));
			}
		}

		$builder->addDefinition($this->prefix('provider'))
			->setFactory(TokenSerializerProvider::class, [$providers]);
	}

}
