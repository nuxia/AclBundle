<?php

namespace Nuxia\AclBundle\Exception;

class OidTypeException extends \InvalidArgumentException
{
    /**
     * @param string $type
     */
    public function __construct($type)
    {
        parent::__construct(sprintf(
            'argument $type for $aclManager->getObjectIdentity() is invalid, "%s" given',
            $type
        ));
    }

}
