<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Key;

use InvalidArgumentException;
use SensitiveParameter;

final class Base64SecurityKey implements SecurityKey
{

    private string $value;

    public function __construct(
        #[SensitiveParameter]
        string $value,
    )
    {
        $decoded = base64_decode($value, true);

        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid base64 string');
        }

        $this->value = $decoded;
    }

    public function getValue(): string
    {
        return $this->value;
    }

}
