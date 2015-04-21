<?php

namespace Nuxia\AclBundle\Manager;

use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\ORM\Query as ORMQuery;
use Doctrine\ORM\QueryBuilder as ORMQueryBuilder;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclFilterInterface
{
    /**
     * @param DBALQueryBuilder|ORMQueryBuilder|ORMQuery $queryBuilder
     * @param string                                    $permission
     * @param string                                    $oidClass
     * @param string                                    $oidReference
     * @param null|UserInterface                        $user
     * @param string[]                                  $orX
     *
     * @return DBALQueryBuilder|ORMQuery
     * @throws \InvalidArgumentException
     */
    public function apply(
        $queryBuilder,
        $permission,
        $oidClass,
        $oidReference,
        UserInterface $user = null,
        array $orX = []
    );
}
