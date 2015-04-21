<?php

namespace Nuxia\AclBundle\Manager;

use Nuxia\AclBundle\Exception\OidTypeException;
use Doctrine\DBAL\Connection;
use Symfony\Component\Security\Acl\Dbal\MutableAclProvider;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Domain\RoleSecurityIdentity;
use Symfony\Component\Security\Acl\Domain\UserSecurityIdentity;
use Symfony\Component\Security\Acl\Model\ObjectIdentityInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\Util\ClassUtils;

class AclIdentifier implements AclIdentifierInterface
{
    /**
     * @var SecurityContextInterface
     */
    protected $tokenStorage;

    /**
     * @var MutableAclProvider
     */
    protected $aclProvider;

    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @var string[]
     */
    protected $aclTables;

    /**
     * @param SecurityContextInterface $tokenStorage
     * @param MutableAclProvider       $aclProvider
     * @param Connection               $connection
     * @param string[]                 $aclTables
     */
    public function __construct(
        SecurityContextInterface $tokenStorage,
        MutableAclProvider $aclProvider,
        Connection $connection,
        array $aclTables
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->aclProvider = $aclProvider;
        $this->connection = $connection;
        $this->aclTables = $aclTables;
    }

    /**
     * {@inheritdoc}
     */
    public function getObjectIdentity($type, $classOrObject)
    {
        if ($classOrObject instanceof ObjectIdentityInterface) {
            return $classOrObject;
        }

        switch ($type) {
            case self::OID_TYPE_CLASS:
                if (is_object($classOrObject)) {
                    $classOrObject = ClassUtils::getRealClass($classOrObject);
                }

                return new ObjectIdentity($type, $classOrObject);
            case self::OID_TYPE_OBJECT:
                return ObjectIdentity::fromDomainObject($classOrObject);
        }

        throw new OidTypeException($type);
    }

    /**
     * {@inheritdoc}
     */
    public function getUserSecurityIdentity(UserInterface $user = null)
    {
        return null === $user
            ? UserSecurityIdentity::fromToken($this->tokenStorage->getToken())
            : UserSecurityIdentity::fromAccount($user);
    }

    /**
     * {@inheritdoc}
     */
    public function getRoleSecurityIdentity($role)
    {
        return new RoleSecurityIdentity($role);
    }

    /**
     * {@inheritdoc}
     */
    public function updateUserSecurityIdentity($oldUsername, UserInterface $user = null)
    {
        $this->aclProvider->updateUserSecurityIdentity(
            $this->getUserSecurityIdentity($user),
            $oldUsername
        );
    }

    /**
     * {@inheritdoc}
     */
    public function updateRoleSecurityIdentity($oldRole, $role)
    {
        $this->connection->executeQuery(sprintf(
            'UPDATE %s SET identifier = %s WHERE username = %s AND identifier = %s',
            $this->aclTables['sid'],
            $this->connection->quote($this->getRoleSecurityIdentity($role)->getRole()),
            $this->connection->getDatabasePlatform()->convertBooleans(false),
            $this->connection->quote($oldRole)
        ));
    }
}
