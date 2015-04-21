<?php

namespace Nuxia\AclBundle\Permission;

use Symfony\Component\Security\Acl\Permission\PermissionMapInterface as SymfonyPermissionMap;

interface PermissionMapInterface extends SymfonyPermissionMap
{
    /**
     * Returns a new instance of the MaskBuilder used in the permissionMap
     *
     * @return MaskBuilderInterface
     */
    public function getMaskBuilder();
}
