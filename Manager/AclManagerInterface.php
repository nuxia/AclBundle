<?php

namespace Nuxia\AclBundle\Manager;

use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclManagerInterface
{
    /**
     * @param string|string[]                       $permissions
     * @param string|object|ObjectIdentityInterface $class
     * @param string|Role                           $role
     * @param null|string                           $field
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null);

    /**
     * @param string|string[]                $permissions
     * @param object|ObjectIdentityInterface $object
     * @param string|Role                    $role
     * @param null|string                    $field
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null);

    /**
     * @param string|string[]                       $permissions
     * @param string|object|ObjectIdentityInterface $class
     * @param null|UserInterface                    $user
     * @param null|string                           $field
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null);

    /**
     * @param string|string[]                $permissions
     * @param object|ObjectIdentityInterface $object
     * @param null|UserInterface             $user
     * @param null|string                    $field
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null);

    /**
     * @param string|string[]                       $permissions
     * @param string|object|ObjectIdentityInterface $class
     * @param string|Role                           $role
     * @param null|string                           $field
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null);

    /**
     * @param string|string[]                $permissions
     * @param object|ObjectIdentityInterface $object
     * @param string|Role                    $role
     * @param null|string                    $field
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null);

    /**
     * @param string|string[]                       $permissions
     * @param string|object|ObjectIdentityInterface $class
     * @param null|UserInterface                    $user
     * @param null|string                           $field
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null);

    /**
     * @param string|string[]                $permissions
     * @param object|ObjectIdentityInterface $object
     * @param null|UserInterface             $user
     * @param null|string                    $field
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null);

    /**
     * @param string|object|ObjectIdentityInterface $class
     */
    public function deleteAclForClass($class);

    /**
     * @param object|ObjectIdentityInterface $object
     */
    public function deleteAclForObject($object);
}
