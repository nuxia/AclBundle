<?php

namespace Nuxia\AclBundle\Manager;

use Nuxia\AclBundle\Exception\OidTypeException;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclIdentifierInterface
{
    const OID_TYPE_CLASS = 'class';
    const OID_TYPE_OBJECT = 'object';

    /**
     * @param string                                $type
     * @param string|object|ObjectIdentityInterface $classOrObject
     *
     * @return ObjectIdentityInterface
     *
     * @throws OidTypeException When the $type is not supported
     */
    public function getObjectIdentity($type, $classOrObject);

    /**
     * @param null|UserInterface $user
     *
     * @return UserSecurityIdentity
     */
    public function getUserSecurityIdentity(UserInterface $user = null);

    /**
     * @param string|Role $role a Role instance, or its string representation
     *
     * @return RoleSecurityIdentity
     */
    public function getRoleSecurityIdentity($role);

    /**
     * @param string             $oldUsername
     * @param UserInterface|null $user
     */
    public function updateUserSecurityIdentity($oldUsername, UserInterface $user = null);

    /**
     * @param string      $oldRole
     * @param string|Role $role
     */
    public function updateRoleSecurityIdentity($oldRole, $role);
}
