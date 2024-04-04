<?php declare(strict_types = 1);

namespace WebChemistry\SecurityToken\Token;

use DateTimeImmutable;
use DateTimeZone;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\JsonToken;
use ParagonIE\Paseto\Keys\Version4\SymmetricKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Protocol\Version4;
use ParagonIE\Paseto\ProtocolCollection;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\IssuedBy;
use ParagonIE\Paseto\Rules\ValidAt;
use SensitiveParameter;
use Throwable;
use WebChemistry\SecurityToken\Key\SecurityKey;
use function _PHPStan_5473b6701\Symfony\Component\String\b;

final class PasetoTokenSerializer implements TokenSerializer
{

    private SymmetricKey $sharedKey;

    /**
     * Generate shared key: `base64_encode(random_bytes(32))`
     */
    public function __construct(
        #[SensitiveParameter]
        SecurityKey $sharedKey,
        private ?string $issuer = null,
    )
    {
        $this->sharedKey = new SymmetricKey($sharedKey->getValue());
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function serialize(array $claims, ?string $expiration = null, ?string $notBefore = null): string
    {
        $timeZone = new DateTimeZone('UTC');

        $builder = new Builder(new JsonToken(), new Version4(), $this->sharedKey);
        $builder->setPurpose(Purpose::local())
            ->setIssuedAt(new DateTimeImmutable(timezone: $timeZone))
            ->setClaims($claims);

        if (($issuer = $this->issuer) !== null) {
            $builder->setIssuer($issuer);
        }

        if ($notBefore !== null) {
            $builder->setNotBefore(new DateTimeImmutable($notBefore, $timeZone));
        } else {
			$builder->setNotBefore(new DateTimeImmutable(timezone: $timeZone));
		}

        if ($expiration !== null) {
            $builder->setExpiration(new DateTimeImmutable($expiration, $timeZone));
        }

        return $builder->toString();
    }

    public function unserialize(string $token, ?string $issuer = null): ?Claims
    {
        $timeZone = new DateTimeZone('UTC');

        $rules = [
            new ValidAt(new DateTimeImmutable(timezone: $timeZone)),
        ];

        if ($issuer !== null) {
            $rules[] = new IssuedBy($issuer);
        }

        $parser = new Parser(ProtocolCollection::v4(), Purpose::local(), $this->sharedKey, $rules);

        try {
            return new Claims($parser->parse($token)->getClaims());
        } catch (PasetoException $e) {
            return null;
        }
    }

}
