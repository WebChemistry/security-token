<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Token;

interface TokenSerializer
{

	/**
	 * @param array<string, mixed> $claims
	 */
	public function serialize(array $claims, ?string $expiration = null, ?string $notBefore = null): string;

	public function unserialize(string $token, ?string $issuer = null): ?Claims;

}
