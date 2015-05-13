<?php

namespace Nuxia\AclBundle\AclManager\Tests\Manager;

use Nuxia\AclBundle\Tests\Model\PostObject;
use Nuxia\AclBundle\Tests\Security\AbstractSecurityTest;
use Doctrine\DBAL\Query\QueryBuilder as DBALQueryBuilder;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Types\Type;
use Doctrine\ORM\Query;
use Symfony\Component\Security\Core\User\UserInterface;

class AclFilterTest extends AbstractSecurityTest
{
    /**
     * @var PostObject[]
     */
    protected $posts = [];

    public function setUp()
    {
        parent::setUp();

        $schema = new Schema();
        $posts = $schema->createTable('posts');
        $posts->addColumn('id', Type::INTEGER);
        $posts->setPrimaryKey(['id']);
        $posts->addColumn('status', Type::STRING);

        $this->connection->exec('DROP TABLE IF EXISTS posts');
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->exec($sql);
        }

        $i = 1;
        while ($i <= 10) {
            $this->posts[$i] = new PostObject($i);
            $this->connection->insert('posts', [
                'id' => $this->posts[$i]->getId(),
                'status' => $this->posts[$i]->getStatus(),
            ]);
            $i++;
        }
    }

    protected function tearDown()
    {
        parent::tearDown();
        $this->connection->exec('DROP TABLE IF EXISTS posts');
    }

    public function testFilter()
    {
        $alice = $this->generateUser('alice', ['ROLE_H_ADMIN']);
        $bob = $this->generateUser('bob', ['ROLE_H_SUPER_ADMIN']);
        $mallory = $this->generateUser('mallory', ['ROLE_H_USER']);
        $this->authenticateUser($alice);

        $this->aclManager->grantRoleOnObject('view', $this->posts[1], 'ROLE_H_USER');
        $this->aclManager->grantRoleOnObject('view', $this->posts[2], 'ROLE_H_ADMIN');
        $this->aclManager->grantRoleOnObject('view', $this->posts[3], 'ROLE_H_SUPER_ADMIN');
        $this->aclManager->grantUserOnObject('view', $this->posts[4], $alice);
        $this->aclManager->grantUserOnObject('edit', $this->posts[5], $alice);
        $this->aclManager->grantUserOnObject('create', $this->posts[6], $alice);

        $this->verify([1, 2, 4, 5], 'view');
        $this->verify([1, 2, 3], 'view', $bob);
        $this->verify([1], 'view', $mallory);
    }

    public function testDoesNotCatchNotGrantedRows()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $this->authenticateUser($alice);

        $this->aclManager->grantUserOnObject('view', $this->posts[1], $alice);
        $this->aclManager->grantUserOnObject('view', $this->posts[2], $bob);

        $this->verify([1], 'view');
    }

    public function testTakesPermissionMapIntoAccount()
    {
        $alice = $this->generateUser('alice');
        $this->authenticateUser($alice);

        $this->aclManager->grantUserOnObject('edit', $this->posts[1]);

        $this->verify([1], 'view');
    }

    public function testWithSimpleRoles()
    {
        $alice = $this->generateUser('alice', ['ROLE_ADMIN']);
        $this->authenticateUser($alice);

        $this->aclManager->grantRoleOnObject('view', $this->posts[1], 'ROLE_USER');

        $this->verify([], 'view');
    }

    public function testWithHierarchyRoles()
    {
        $alice = $this->generateUser('alice', ['ROLE_H_ADMIN']);
        $this->authenticateUser($alice);

        $this->aclManager->grantRoleOnObject('view', $this->posts[1], 'ROLE_H_USER');
        $this->aclManager->grantRoleOnClass('view', $this->posts[1], 'ROLE_H_USER');

        $this->verify([1], 'view');
    }

    public function testWithOrX()
    {
        $alice = $this->generateUser('alice');
        $this->authenticateUser($alice);

        $this->aclManager->grantUserOnObject('view', $this->posts[3], $alice);
        $this->aclManager->grantUserOnObject('view', $this->posts[9], $alice);

        $this->verify([2, 3, 4, 6, 8, 9, 10], 'view', $alice, ['p.status = \'even\'']);
        $this->verify([2, 3, 4, 5, 6, 8, 9, 10], 'view', $alice, ['p.status = \'even\'', 'p.id = 5']);
    }

    public function testWithWhere()
    {
        $alice = $this->generateUser('alice');
        $this->authenticateUser($alice);

        $this->aclManager->grantUserOnObject('view', $this->posts[3], $alice);
        $this->aclManager->grantUserOnObject('view', $this->posts[9], $alice);

        $this->verify([3], 'view', null, [], 'p.id IN (1, 2, 3)');
    }

    public function testWithWhereAndOrX()
    {
        $alice = $this->generateUser('alice');
        $this->authenticateUser($alice);

        $this->aclManager->grantUserOnObject('view', $this->posts[3], $alice);
        $this->aclManager->grantUserOnObject('view', $this->posts[9], $alice);

        $this->verify([2, 3], 'view', null, ['p.status = \'even\''], 'p.id IN (1, 2, 3)');
    }

    /**
     * @param int[]         $expected
     * @param string        $permission
     * @param UserInterface $user
     * @param string[]      $orX
     * @param string        $where
     */
    private function verify(array $expected, $permission, UserInterface $user = null, array $orX = [], $where = null)
    {
        $fails = [];
        $permission = strtoupper($permission);

        $DBALQueryBuilder = new DBALQueryBuilder($this->connection);
        $DBALQueryBuilder->select('*')->from('posts', 'p');
        if (null !== $where) {
            $DBALQueryBuilder->where($where);
        }
        $this->aclFilter->apply($DBALQueryBuilder, $permission, 'Nuxia\AclBundle\Tests\Model\PostObject', 'p.id', $user, $orX);
        try {
            $this->assertEquals(
                $expected,
                $this->getPostIds($DBALQueryBuilder),
                'DBALQueryBuilder failed'
            );
        } catch (\PHPUnit_Framework_ExpectationFailedException $e) {
            $fails[] = $e;
        }

        $ORMQueryBuilder = $this->em->createQueryBuilder();
        $ORMQueryBuilder->select('p')->from('Nuxia\AclBundle\Tests\Model\PostObject', 'p');
        if (null !== $where) {
            $ORMQueryBuilder->where($where);
        }
        $cloneORMQueryBuilder = clone $ORMQueryBuilder;
        $query = $this->aclFilter->apply($ORMQueryBuilder, $permission, 'Nuxia\AclBundle\Tests\Model\PostObject', 'p.id', $user, $orX);
        try {
            $this->assertEquals(
                $expected,
                $this->getPostIds($query),
                'ORMQueryBuilder failed'
            );
        } catch (\PHPUnit_Framework_ExpectationFailedException $e) {
            $fails[] = $e;
        }

        $query = $this->aclFilter->apply($cloneORMQueryBuilder->getQuery(), $permission, 'Nuxia\AclBundle\Tests\Model\PostObject', 'p.id', $user, $orX);
        try {
            $this->assertEquals(
                $expected,
                $this->getPostIds($query),
                'ORMQuery failed'
            );
        } catch (\PHPUnit_Framework_ExpectationFailedException $e) {
            $fails[] = $e;
        }

        if (!empty($fails)) {
            $messages = [];
            /** @var \PHPUnit_Framework_ExpectationFailedException $e */
            foreach ($fails as $e) {
                $messages[] = $e->getMessage().$e->getComparisonFailure()->getDiff();
            }

            $this->fail(implode(PHP_EOL, $messages));
        }
    }

    /**
     * @param DBALQueryBuilder|Query $queryBuilder
     *
     * @return int[]
     */
    private function getPostIds($queryBuilder)
    {
        $ids = [];

        if ($queryBuilder instanceof DBALQueryBuilder) {
            foreach ($queryBuilder->execute()->fetchAll() as $post) {
                $ids[] = (int) $post['id'];
            }
        } elseif ($queryBuilder instanceof Query) {
            foreach ($queryBuilder->getResult() as $post) {
                $ids[] = $post->getId();
            }
        }

        return array_unique($ids);
    }
}
