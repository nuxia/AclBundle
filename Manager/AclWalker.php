<?php

namespace Nuxia\AclBundle\Manager;

use Doctrine\ORM\Mapping\ClassMetadata;
use Doctrine\ORM\Query\Expr\Orx;
use Doctrine\ORM\Query\SqlWalker;

class AclWalker extends SqlWalker
{
    /**
     * @param \Doctrine\ORM\Query\AST\FromClause $fromClause
     * @return string
     */
    public function walkFromClause($fromClause)
    {
        $sql = parent::walkFromClause($fromClause) . ' ';

        $aclJoin = $this->getQuery()->getHint('acl_join');
        $oidReference = $this->getQuery()->getHint('acl_filter_oid_reference');
        $orX = $this->getQuery()->getHint('acl_filter_or_x');

        $joinType = empty($orX) ? 'INNER' : 'LEFT';
        $newOidReference = $this->DQLToSQLReference($oidReference);


        $sql .= <<<SQL
{$joinType} JOIN ($aclJoin) acl ON {$newOidReference} = acl.object_identifier
SQL;

        return $sql;
    }

    /**
     * @param \Doctrine\ORM\Query\AST\WhereClause $whereClause
     * @return string
     */
    public function walkWhereClause($whereClause)
    {
        $sql =  parent::walkWhereClause($whereClause);

        $aclWhereClause = $this->getQuery()->getHint('acl_where_clause');
        $orX = $this->getQuery()->getHint('acl_filter_or_x');

        $sql .= empty($sql) ? ' WHERE (' : ' AND (';

        if (!empty($orX)) {
            foreach ($orX as $key => $or) {
                preg_match_all("/\w+\.{1}\w+/", $or, $orReferences);

                foreach ($orReferences as $orReference) {
                    $orX[$key] = str_replace($orReference[0], $this->DQLToSQLReference($orReference[0]), $or);
                }
            }

            $sql .= '(' . new Orx($orX) . ') OR ';
        }

        $sql .= '(' . $aclWhereClause . '))';

        return $sql;
    }

    /**
     * @param string $reference
     *
     * @return string
     */
    private function DQLToSQLReference($reference)
    {
        $explode = explode('.', $reference, 2);
        /** @var ClassMetadata $metadata */
        $metadata = $this->getQueryComponent($explode[0])['metadata'];
        $tableReference = $metadata->table['name'];
        $aliasReference = $this->getSQLTableAlias($tableReference, $explode[0]);
        $columnName = $metadata->fieldMappings[$explode[1]]['columnName'];

        return $aliasReference . '.' . $columnName;
    }
}
