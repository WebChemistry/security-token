<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Key;

interface SecurityKey
{

    public function getValue(): string;

}
