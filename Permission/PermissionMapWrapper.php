<?php

namespace Nuxia\AclBundle\Permission;

use Symfony\Component\Security\Acl\Permission\MaskBuilderRetrievalInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface as SymfonyPermissionMapInterface;

class PermissionMapWrapper implements PermissionMapInterface
{
    /**
     * @var SymfonyPermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @var string
     */
    protected $maskBuilderClass;

    /**
     * @param SymfonyPermissionMapInterface $permissionMap
     */
    public function __construct(SymfonyPermissionMapInterface $permissionMap)
    {
        $this->permissionMap = $permissionMap;
        $this->maskBuilderClass = $permissionMap instanceof MaskBuilderRetrievalInterface
            ? get_class($permissionMap->getMaskBuilder())
            : 'Nuxia\AclBundle\Permission\BasicMaskBuilder';
    }

    /**
     * {@inheritdoc}
     */
    public function contains($permission)
    {
        return $this->permissionMap->contains($permission);
    }

    /**
     * {@inheritdoc}
     */
    public function getMasks($permission, $object)
    {
        return $this->permissionMap->getMasks($permission, $object);
    }

    /**
     * {@inheritdoc}
     */
    public function getMaskBuilder()
    {
        return new $this->maskBuilderClass();
    }
}
