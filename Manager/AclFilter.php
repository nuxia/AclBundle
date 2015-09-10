<?php

namespace Nuxia\AclBundle\Manager;

use Nuxia\AclBundle\Permission\PermissionMapInterface;
use Nuxia\AclBundle\Permission\PermissionMapWrapper;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\ORM\Query as ORMQuery;
use Doctrine\ORM\QueryBuilder as ORMQueryBuilder;
use Symfony\Component\Security\Acl\Domain\PermissionGrantingStrategy;
use Symfony\Component\Security\Acl\Permission\PermissionMapInterface as SymfonyPermissionMapInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilter implements AclFilterInterface
{
    /**
     * @var AclIdentifierInterface
     */
    protected $aclIdentifier;

    /**
     * @var RoleHierarchyInterface
     */
    protected $roleHierarchy;

    /**
     * @var TokenStorageInterface|SecurityContextInterface
     */
    protected $tokenStorage;

    /**
     * @var array
     */
    protected $aclTables;
    /**
     * @var PermissionMapInterface
     */
    protected $permissionMap;

    /**
     * @var string
     */
    protected $aclWalker;

    /**
     * @param AclIdentifierInterface                         $aclIdentifier
     * @param RoleHierarchyInterface                         $roleHierarchy
     * @param TokenStorageInterface|SecurityContextInterface $tokenStorage
     * @param array                                          $aclTables
     */
    public function __construct(
        AclIdentifierInterface $aclIdentifier,
        RoleHierarchyInterface $roleHierarchy,
        $tokenStorage,
        array $aclTables
    ) {
        if (!$tokenStorage instanceof TokenStorageInterface && !$tokenStorage instanceof SecurityContextInterface) {
            throw new \InvalidArgumentException('Argument 3 should be an instance of Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface or Symfony\Component\Security\Core\SecurityContextInterface');
        }

        $this->aclIdentifier = $aclIdentifier;
        $this->roleHierarchy = $roleHierarchy;
        $this->tokenStorage = $tokenStorage;
        $this->aclTables = $aclTables;
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
     * @param string $aclWalker
     */
    public function setAclWalker($aclWalker)
    {
        $this->aclWalker = $aclWalker;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(
        $queryBuilder,
        $permission,
        $oidClass,
        $oidReference,
        UserInterface $user = null,
        array $orX = []
    ) {
        if ($queryBuilder instanceof DBALQueryBuilder) {
            $connection = $queryBuilder->getConnection();

            $explode = explode('.', $oidReference, 2);
            $fromAlias = $explode[0];

            $queryBuilder->add('join', [
                $fromAlias => [
                    'joinType' => empty($orX) ? 'inner' : 'left',
                    'joinTable' => '('.$this->getAclJoin($connection, $oidClass, $user).')',
                    'joinAlias' => 'acl',
                    'joinCondition' => $oidReference.' = CAST(acl.object_identifier AS INTEGER)',
                ],
            ], true);

            $orX[] = $this->getAclWhereClause($connection, $permission);

            $queryBuilder->andWhere(call_user_func_array([$connection->getExpressionBuilder(), 'orX'], $orX));

            return $queryBuilder;
        }

        if ($queryBuilder instanceof ORMQueryBuilder || $queryBuilder instanceof ORMQuery) {
            $connection = $queryBuilder->getEntityManager()->getConnection();

            $query = $queryBuilder instanceof ORMQueryBuilder ? $queryBuilder->getQuery() : $queryBuilder;
            $query->setHint('acl_join', $this->getAclJoin($connection, $oidClass, $user));
            $query->setHint('acl_where_clause', $this->getAclWhereClause($connection, $permission));
            $query->setHint('acl_filter_oid_reference', $oidReference);
            $query->setHint('acl_filter_or_x', $orX);
            $query->setHint(ORMQuery::HINT_CUSTOM_OUTPUT_WALKER, $this->aclWalker);

            return $query;
        }

        throw new \InvalidArgumentException(sprintf('AclFilter only supports %s, %s or %s.',
            'Doctrine\DBAL\Query\QueryBuilder',
            'Doctrine\ORM\Query',
            'Doctrine\ORM\QueryBuilder'
        ));
    }

    /**
     * @param Connection    $connection
     * @param string        $oidClass
     * @param UserInterface $user
     *
     * @return string
     */
    private function getAclJoin(Connection $connection, $oidClass, UserInterface $user = null)
    {
        $sidIds = $this->findSidIds($connection, $user);

        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->select('acl_o.object_identifier', 'acl_e.granting', 'acl_e.granting_strategy', 'acl_e.mask')
            ->from($this->aclTables['entry'], 'acl_e')
            ->innerJoin('acl_e', $this->aclTables['oid'], 'acl_o', 'acl_e.object_identity_id = acl_o.id')
            ->where('acl_e.class_id = '.$this->findClassId($connection, $oidClass))
            ->andWhere(
                empty($sidIds) ? '1 = 2' : $queryBuilder->expr()->in('acl_e.security_identity_id', $sidIds)
            );

        return $queryBuilder->getSQL();
    }

    /**
     * @param Connection $connection
     * @param $permission
     *
     * @return string
     *
     * @throws \Exception
     */
    private function getAclWhereClause(Connection $connection, $permission)
    {
        $sql = 'acl.granting = true AND (';

        $requiredMasks = $this->permissionMap->getMasks($permission, null);

        if (empty($requiredMasks)) {
            throw new \Exception('The required masks can not be resolved');
        }

        $all = $connection->quote(PermissionGrantingStrategy::ALL);
        $any = $connection->quote(PermissionGrantingStrategy::ANY);
        $equal = $connection->quote(PermissionGrantingStrategy::EQUAL);

        $conditions = [];
        foreach ($requiredMasks as $requiredMask) {
            $conditions[] = <<<SQL
(
  (acl.granting_strategy = {$all} AND {$requiredMask} = (acl.mask & {$requiredMask}))
  OR (acl.granting_strategy = {$any} AND 0 != (acl.mask & {$requiredMask}))
  OR (acl.granting_strategy = {$equal} AND {$requiredMask} = acl.mask)
)
SQL;
        }

        return $sql.implode(' OR ', $conditions).')';
    }

    /**
     * @param Connection $connection
     * @param string     $oidClass
     *
     * @return int
     */
    private function findClassId(Connection $connection, $oidClass)
    {
        return (int) $connection->fetchColumn(
            'SELECT acl_c.id FROM '.$this->aclTables['class'].' acl_c WHERE acl_c.class_type = :oid_class',
            ['oid_class' => $oidClass]
        );
    }

    /**
     * @param Connection    $connection
     * @param UserInterface $user
     *
     * @return int[]
     */
    private function findSidIds(Connection $connection, UserInterface $user = null)
    {
        $userSid = $this->aclIdentifier->getUserSecurityIdentity($user);

        $queryBuilder = $connection->createQueryBuilder();
        $queryBuilder
            ->select('acl_s.id')
            ->from($this->aclTables['sid'], 'acl_s')
            ->where('acl_s.username = true AND acl_s.identifier = :identifier')
            ->setParameter('identifier', $userSid->getClass().'-'.$userSid->getUsername());

        if (null === $user && null !== $this->tokenStorage->getToken()) {
            $user = $this->tokenStorage->getToken()->getUser();
        }

        if ($user instanceof UserInterface) {
            $roles = $this->roleHierarchy->getReachableRoles(array_map(function ($role) {
                if (is_string($role)) {
                    $role = new Role($role);
                }

                return $role;
            }, $user->getRoles()));

            $roles = array_map(function (RoleInterface $role) {
                return $role->getRole();
            }, $roles);

            if (!empty($roles)) {
                $queryBuilder
                    ->orWhere('acl_s.username = false AND acl_s.identifier IN (:roles)')
                    ->setParameter('roles', $roles, Connection::PARAM_STR_ARRAY);
            }
        }

        return array_map(function (array $row) {
            return (int) $row['id'];
        }, $queryBuilder->execute()->fetchAll());
    }
}
