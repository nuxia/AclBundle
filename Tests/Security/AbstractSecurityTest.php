<?php

namespace Nuxia\AclBundle\Tests\Security;

use Nuxia\AclBundle\Manager\AclCheckerInterface;
use Nuxia\AclBundle\Manager\AclFilter;
use Nuxia\AclBundle\Manager\AclIdentifierInterface;
use Nuxia\AclBundle\Manager\AclManagerInterface;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Tools\Setup;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\Security\Acl\Dbal\Schema;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;

class AbstractSecurityTest extends WebTestCase
{
    /**
     * @var Client
     */
    protected $client;

    /**
     * @var ContainerInterface
     */
    protected $container;

    /**
     * @var TokenInterface
     */
    protected $token;

    /**
     * @var Connection
     */
    protected $connection;

    /**
     * @var EntityManager
     */
    protected $em;

    /**
     * @var AclManagerInterface
     */
    protected $aclManager;

    /**
     * @var AclCheckerInterface
     */
    protected $aclChecker;

    /**
     * @var AclFilter
     */
    protected $aclFilter;

    /**
     * @var AclIdentifierInterface
     */
    protected $aclIdentifier;

    /**
     * @var array
     */
    protected $tableNames;

    public function setUp()
    {
        $this->client = static::createClient();
        $this->container = $this->client->getContainer();

        $this->connection = $this->container->get('database_connection');

        $config = Setup::createAnnotationMetadataConfiguration([__DIR__ . '/../Model'], true);
        $this->em = EntityManager::create($this->connection, $config);

        $this->tableNames = array(
            'entry_table_name' => 'acl_entries',
            'sid_table_name' => 'acl_security_identities',
            'class_table_name' => 'acl_classes',
            'oid_ancestors_table_name' => 'acl_object_identity_ancestors',
            'oid_table_name' => 'acl_object_identities',
        );

        if (!class_exists('PDO') || !in_array('sqlite', \PDO::getAvailableDrivers())) {
            $this->markTestSkipped('This test requires SQLite support in your environment.');
        }

        $this->cleanDB();
        $this->createDB();

        $this->aclManager = $this->container->get('nuxia_acl.acl_manager');
        $this->aclChecker = $this->container->get('nuxia_acl.acl_checker');
        $this->aclFilter = $this->container->get('nuxia_acl.acl_filter');
        $this->aclIdentifier = $this->container->get('nuxia_acl.acl_identifier');
    }

    protected function tearDown()
    {
        $this->cleanDB();
    }

    protected function createDB()
    {
        $schema = new Schema($this->tableNames);
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->exec($sql);
        }
    }

    protected function cleanDB()
    {
        foreach ($this->tableNames as $table) {
            $this->connection->query(sprintf('DROP TABLE IF EXISTS %s;', $table));
        }
    }

    /**
     * @param string      $username
     * @param array $roles
     *
     * @return User
     */
    protected function generateUser($username, array $roles = ['ROLE_USER'])
    {
        return new User($username, null, $roles);
    }

    /**
     * @param UserInterface $user
     */
    protected function authenticateUser(UserInterface $user)
    {
        $this->token = $this->createToken($user);
        $this->container->get('security.context')->setToken($this->token);
        $this->assertTrue($this->token->isAuthenticated());
    }

    /**
     * @param UserInterface $user
     *
     * @return UsernamePasswordToken
     */
    protected function createToken(UserInterface $user)
    {
        $token = new UsernamePasswordToken($user, '', 'main', $user->getRoles());

        return $token;
    }

    public function testIfContainerExists()
    {
        $this->assertNotNull($this->client);
        $this->assertNotNull($this->container);
    }
}
