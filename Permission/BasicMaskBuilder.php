<?php

namespace Nuxia\AclBundle\Permission;

use Symfony\Component\Security\Acl\Permission\MaskBuilder;

final class BasicMaskBuilder extends AbstractMaskBuilder
{
    /**
     * Returns a human-readable representation of the permission.
     *
     * @return string
     */
    public function getPattern()
    {
        $originalMaskBuilder = new MaskBuilder($this->mask);

        return $originalMaskBuilder->getPattern();
    }

    /**
     * Returns the code for the passed mask.
     *
     * @param int $mask
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     *
     * @return string
     */
    public static function getCode($mask)
    {
        MaskBuilder::getCode($mask);
    }

    /**
     * Returns the mask for the passed code.
     *
     * @param mixed $code
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function resolveMask($code)
    {
        if (is_string($code)) {
            if (!defined($name = sprintf('Symfony\Component\Security\Acl\Permission\MaskBuilder::MASK_%s', strtoupper($code)))) {
                throw new \InvalidArgumentException(sprintf('The code "%s" is not supported', $code));
            }

            return constant($name);
        }

        if (!is_int($code)) {
            throw new \InvalidArgumentException('$code must be an integer.');
        }

        return $code;
    }
}
