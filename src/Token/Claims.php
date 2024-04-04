<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Token;

final class Claims
{

    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private array $claims,
    )
    {
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

}
