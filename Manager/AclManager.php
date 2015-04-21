<?php

namespace Nuxia\AclBundle\Manager;

use Nuxia\AclBundle\Permission\PermissionMapInterface;
use Nuxia\AclBundle\Permission\PermissionMapWrapper;
use Symfony\Component\Security\Acl\Domain\Entry;
use Symfony\Component\Security\Acl\Exception\AclNotFoundException;
use Symfony\Component\Security\Acl\Model\AclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclInterface;
use Symfony\Component\Security\Acl\Model\MutableAclProviderInterface;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Acl\Model\SecurityIdentityInterface;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface as SymfonyPermissionMapInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclManager implements AclManagerInterface
{
    /**
     * @var AclIdentifierInterface
     */
    protected $aclIdentifier;

    /**
     * @var MutableAclProviderInterface $aclProvider
     */
    protected $aclProvider;

    /**
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @param AclIdentifierInterface      $aclIdentifier
     * @param MutableAclProviderInterface $aclProvider
     */
    public function __construct(
        AclIdentifierInterface $aclIdentifier,
        MutableAclProviderInterface $aclProvider
    ) {
        $this->aclIdentifier = $aclIdentifier;
        $this->aclProvider = $aclProvider;
    }

    /**
     * @param SymfonyPermissionMapInterface $permissionMap
     */
    public function setPermissionMap(SymfonyPermissionMapInterface $permissionMap)
    {
        if (!$permissionMap instanceof PermissionMapInterface) {
            $permissionMap = new PermissionMapWrapper($permissionMap);
        }

        $this->permissionMap = $permissionMap;
    }

    /**
     * {@inheritdoc}
     */
    public function grantRoleOnClass($permissions, $class, $role, $field = null)
    {
        $this->grant(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class),
            $this->aclIdentifier->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantRoleOnObject($permissions, $object, $role, $field = null)
    {
        $this->grant(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object),
            $this->aclIdentifier->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_OBJECT,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $this->grant(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class),
            $this->aclIdentifier->getUserSecurityIdentity($user),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
        $this->grant(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object),
            $this->aclIdentifier->getUserSecurityIdentity($user),
            $permissions,
            AclIdentifierInterface::OID_TYPE_OBJECT,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnClass($permissions, $class, $role, $field = null)
    {
        $this->revoke(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class),
            $this->aclIdentifier->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function revokeRoleOnObject($permissions, $object, $role, $field = null)
    {
        $this->revoke(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object),
            $this->aclIdentifier->getRoleSecurityIdentity($role),
            $permissions,
            AclIdentifierInterface::OID_TYPE_OBJECT,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
    {
        $this->revoke(
            $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class),
            $this->aclIdentifier->getUserSecurityIdentity($user),
            $permissions,
            AclIdentifierInterface::OID_TYPE_CLASS,
            $field
        );
    }
    /**
     * {@inheritdoc}
     */
    public function revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
    {
         $this->revoke(
             $this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object),
             $this->aclIdentifier->getUserSecurityIdentity($user),
             $permissions,
             AclIdentifierInterface::OID_TYPE_OBJECT,
             $field
        );
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForClass($class)
    {
        $this->aclProvider->deleteAcl($this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_CLASS, $class));
    }

    /**
     * {@inheritdoc}
     */
    public function deleteAclForObject($object)
    {
        $this->aclProvider->deleteAcl($this->aclIdentifier->getObjectIdentity(AclIdentifierInterface::OID_TYPE_OBJECT, $object));
    }

    /**
     * @param ObjectIdentityInterface   $objectIdentity
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|string[]           $permissions
     * @param string                    $type
     * @param null|string               $field
     */
    protected function grant(ObjectIdentityInterface $objectIdentity, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        $acl = $this->findOrCreateAcl($objectIdentity);

        $index = false;
        $oldMask = 0;
        /** @var Entry $ace */
        foreach ($acl->{$this->resolveAceMethod('get', $type, $field)}($field) as $k => $ace) {
            if ($securityIdentity->equals($ace->getSecurityIdentity())) {
                $index = $k;
                $oldMask = $ace->getMask();

                continue;
            }
        }

        $maskBuilder = $this->permissionMap->getMaskBuilder();
        $maskBuilder->set($oldMask);

        foreach ((array) $permissions as $permission) {
            $maskBuilder->add($permission);
        }

        if (false === $index) {
            if (null === $field) {
                $acl->{$this->resolveAceMethod('insert', $type)}($securityIdentity, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('insert', $type, $field)}($field, $securityIdentity, $maskBuilder->get());
            }
        } else {
            if (null === $field) {
                $acl->{$this->resolveAceMethod('update', $type)}($index, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $field, $maskBuilder->get());
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param ObjectIdentityInterface   $objectIdentity
     * @param SecurityIdentityInterface $securityIdentity
     * @param string|string[]           $permissions
     * @param string                    $type
     * @param null|string               $field
     */
    protected function revoke(ObjectIdentityInterface $objectIdentity, SecurityIdentityInterface $securityIdentity, $permissions, $type, $field = null)
    {
        if (null === $acl = $this->findAcl($objectIdentity)) {
            return;
        }

        $index = false;
        $oldMask = 0;
        /** @var Entry $ace */
        foreach ($acl->{$this->resolveAceMethod('get', $type, $field)}($field) as $k => $ace) {
            if ($securityIdentity->equals($ace->getSecurityIdentity())) {
                $index = $k;
                $oldMask = $ace->getMask();

                continue;
            }
        }

        if (false !== $index) {
            $maskBuilder = $this->permissionMap->getMaskBuilder();
            $maskBuilder->set($oldMask);

            foreach ((array) $permissions as $permission) {
                $maskBuilder->remove($permission);
            }

            if (null === $field) {
                $acl->{$this->resolveAceMethod('update', $type)}($index, $maskBuilder->get());
            } else {
                $acl->{$this->resolveAceMethod('update', $type, $field)}($index, $field, $maskBuilder->get());
            }
        }

        $this->aclProvider->updateAcl($acl);
    }

    /**
     * @param string      $method get|insert|update|delete
     * @param string      $type
     * @param null|string $field
     *
     * @return string
     */
    protected function resolveAceMethod($method, $type, $field = null)
    {
        $result = $method . ucfirst($type);

        if (null !== $field) {
            $result .= 'Field';
        }

        $result .= 'Ace';

        if ('get' === $method) {
            $result .= 's';
        }

        return $result;
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return AclInterface|MutableAclInterface
     */
    protected function findOrCreateAcl(ObjectIdentityInterface $objectIdentity)
    {
        try {
            return $this->aclProvider->findAcl($objectIdentity);
        } catch (AclNotFoundException $e) {
            return $this->aclProvider->createAcl($objectIdentity);
        }
    }

    /**
     * @param ObjectIdentityInterface $objectIdentity
     *
     * @return null|AclInterface
     */
    protected function findAcl(ObjectIdentityInterface $objectIdentity)
    {
        try {
            return $this->aclProvider->findAcl($objectIdentity);
        } catch (AclNotFoundException $e) {
            return null;
        }
    }
}
