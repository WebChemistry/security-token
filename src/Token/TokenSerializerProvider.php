<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Token;

use InvalidArgumentException;

class TokenSerializerProvider
{

	/**
	 * @param array<string, TokenSerializer> $providers
	 */
	public function __construct(
		private array $providers,
	)
	{
	}

	public function get(?string $name = null): TokenSerializer
	{
		$key = $name ?? 'default';

		return $this->providers[$key] ?? throw new InvalidArgumentException(sprintf('Token serializer "%s" not found', $key));
	}

}
