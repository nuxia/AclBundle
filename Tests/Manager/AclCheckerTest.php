<?php

namespace Nuxia\AclBundle\AclManager\Tests\Manager;

use Nuxia\AclBundle\Tests\Security\AbstractSecurityTest;
use Nuxia\AclBundle\Tests\Model\BarObject;
use Nuxia\AclBundle\Tests\Model\FooObject;

class AclCheckerTest extends AbstractSecurityTest
{
    const ROLE_USER = 'ROLE_USER';
    const ROLE_ADMIN = 'ROLE_ADMIN';
    const ROLE_SUPER_ADMIN = 'ROLE_SUPER_ADMIN';

    protected $fooClass;

    protected $barClass;

    public function setUp()
    {
        parent::setUp();
        $this->fooClass = 'Nuxia\AclBundle\Tests\Model\FooObject';
        $this->barClass = 'Nuxia\AclBundle\Tests\Model\BarObject';
    }

    public function test_is_granted_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $b, $bob);

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $b));

        $this->authenticateUser($bob);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $b));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW', 'DELETE'], $b));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $b));
    }

    public function test_is_granted_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $this->barClass, $bob);

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->barClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $this->fooClass));

        $this->authenticateUser($bob);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $this->barClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW', 'DELETE'], $this->barClass));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->barClass));
    }

    public function test_is_granted_field_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $a, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $b, $bob, 'securedField');

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));

        $this->authenticateUser($bob);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $b, 'securedField'));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $b, 'securedField'));
    }

    public function test_is_granted_field_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $this->fooClass, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $this->barClass, $bob, 'securedField');

        $this->authenticateUser($alice);
        $this->assertTrue($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass(['VIEW', 'EDIT'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));

        $this->authenticateUser($bob);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $this->fooClass, 'securedField'));

        $this->assertTrue($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));
        $this->assertTrue($this->aclChecker->isGrantedOnClass('EDIT', $this->barClass, 'securedField'));

        $this->authenticateUser($mallory);
        $this->assertFalse($this->aclChecker->isGrantedOnClass('VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass(['EDIT', 'VIEW'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('MASTER', $this->fooClass, 'foo'));
        $this->assertFalse($this->aclChecker->isGrantedOnClass('EDIT', $this->barClass, 'securedField'));
    }

    public function test_role_is_granted_on_class_with_class()
    {
        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT'], $this->fooClass, self::ROLE_USER);
        $this->aclManager->grantRoleOnClass('MASTER', $this->barClass, self::ROLE_ADMIN);

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->barClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, ['VIEW', 'EDIT'], $this->fooClass));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'MASTER', $this->barClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'VIEW', $this->fooClass));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, ['EDIT', 'VIEW', 'DELETE'], $this->barClass));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'VIEW', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $this->fooClass));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'MASTER', $this->barClass));
    }

    public function test_role_is_granted_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT'], $a, self::ROLE_USER);
        $this->aclManager->grantRoleOnClass('MASTER', $b, self::ROLE_ADMIN);

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $b));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'MASTER', $b));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'VIEW', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, ['EDIT', 'VIEW', 'DELETE'], $b));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'VIEW', $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'MASTER', $b));
    }

    public function test_role_is_granted_field_on_class_with_class()
    {
        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT'], $this->fooClass, self::ROLE_USER, 'securedField');
        $this->aclManager->grantRoleOnClass('MASTER', $this->fooClass, self::ROLE_ADMIN, 'foo');
        $this->aclManager->grantRoleOnClass('EDIT', $this->barClass, self::ROLE_ADMIN, 'securedField');

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, ['VIEW', 'EDIT'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'MASTER', $this->fooClass, 'foo'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, ['EDIT', 'VIEW'], $this->fooClass, 'securedField'));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'MASTER', $this->fooClass, 'foo'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'EDIT', $this->barClass, 'securedField'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, ['EDIT', 'VIEW'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'MASTER', $this->fooClass, 'foo'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $this->barClass, 'securedField'));
    }

    public function test_role_is_granted_field_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $this->aclManager->grantRoleOnClass(['VIEW', 'EDIT'], $a, self::ROLE_USER, 'securedField');
        $this->aclManager->grantRoleOnClass('MASTER', $a, self::ROLE_ADMIN, 'foo');
        $this->aclManager->grantRoleOnClass('EDIT', $b, self::ROLE_ADMIN, 'securedField');

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, ['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_USER, 'MASTER', $a, 'foo'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, ['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnClass(self::ROLE_ADMIN, 'EDIT', $b, 'securedField'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, ['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnClass(self::ROLE_SUPER_ADMIN, 'EDIT', $b, 'securedField'));
    }

    public function test_role_is_granted_on_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $this->aclManager->grantRoleOnObject(['VIEW', 'EDIT'], $a, self::ROLE_USER);
        $this->aclManager->grantRoleOnObject('MASTER', $b, self::ROLE_ADMIN);

        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $b));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'MASTER', $b));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'VIEW', $a));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, ['EDIT', 'VIEW', 'DELETE'], $b));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'VIEW', $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'EDIT', $a));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'MASTER', $b));
    }

    public function test_role_is_granted_field_on_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $this->aclManager->grantRoleOnObject(['VIEW', 'EDIT'], $a, self::ROLE_USER, 'securedField');
        $this->aclManager->grantRoleOnObject('MASTER', $a, self::ROLE_ADMIN, 'foo');
        $this->aclManager->grantRoleOnObject('EDIT', $b, self::ROLE_ADMIN, 'securedField');

        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, ['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_USER, 'MASTER', $a, 'foo'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, ['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->roleIsGrantedOnObject(self::ROLE_ADMIN, 'EDIT', $b, 'securedField'));

        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, ['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->roleIsGrantedOnObject(self::ROLE_SUPER_ADMIN, 'EDIT', $b, 'securedField'));
    }

    public function test_user_is_granted_field_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $this->fooClass, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $this->barClass, $bob, 'securedField');

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, ['VIEW', 'EDIT'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'MASTER', $this->fooClass, 'foo'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, ['EDIT', 'VIEW'], $this->fooClass, 'securedField'));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'MASTER', $this->fooClass, 'foo'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $this->barClass, 'securedField'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'VIEW', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, ['EDIT', 'VIEW'], $this->fooClass, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'MASTER', $this->fooClass, 'foo'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $this->barClass, 'securedField'));
    }

    public function test_user_is_granted_field_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice, 'securedField');
        $this->aclManager->grantUserOnClass('MASTER', $a, $bob, 'foo');
        $this->aclManager->grantUserOnClass('EDIT', $b, $bob, 'securedField');

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, ['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'MASTER', $a, 'foo'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($bob, ['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $b, 'securedField'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, ['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $b, 'securedField'));
    }

    public function test_user_is_granted_on_class_with_class()
    {
        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $this->fooClass, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $this->fooClass, $bob);
        $this->aclManager->grantUserOnClass('EDIT', $this->barClass, $bob);

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, ['VIEW', 'EDIT'], $this->fooClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, ['VIEW', 'EDIT'], $this->fooClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $this->fooClass));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'MASTER', $this->fooClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'MASTER', $this->fooClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'MASTER', $this->fooClass));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $this->barClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $this->barClass));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $this->barClass));
    }

    public function test_user_is_granted_on_class_with_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnClass(['VIEW', 'EDIT'], $a, $alice);
        $this->aclManager->grantUserOnClass('MASTER', $a, $bob);
        $this->aclManager->grantUserOnClass('EDIT', $b, $bob);

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($alice, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'DELETE', $a));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'MASTER', $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'MASTER', $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'MASTER', $a));

        $this->assertTrue($this->aclChecker->userIsGrantedOnClass($bob, 'EDIT', $b));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($mallory, 'EDIT', $b));
        $this->assertFalse($this->aclChecker->userIsGrantedOnClass($alice, 'EDIT', $b));
    }

    public function test_user_is_granted_on_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnObject(['VIEW', 'EDIT'], $a, $alice);
        $this->aclManager->grantUserOnObject('MASTER', $a, $bob);
        $this->aclManager->grantUserOnObject('EDIT', $b, $bob);

        $this->aclManager->grantUserOnClass('DELETE', $b, $bob);

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, ['VIEW', 'EDIT'], $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'DELETE', $a));

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($bob, 'MASTER', $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'MASTER', $a));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'MASTER', $a));

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($bob, 'EDIT', $b));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'EDIT', $b));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $b));

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($bob, 'DELETE', $b));
    }

    public function test_user_is_granted_field_on_object()
    {
        $a = new FooObject(uniqid());
        $b = new BarObject(uniqid());
        $b2 = new BarObject(uniqid());

        $alice = $this->generateUser('alice');
        $bob = $this->generateUser('bob');
        $mallory = $this->generateUser('mallory');

        $this->aclManager->grantUserOnObject(['VIEW', 'EDIT'], $a, $alice, 'securedField');
        $this->aclManager->grantUserOnObject('MASTER', $a, $bob, 'foo');
        $this->aclManager->grantUserOnObject('EDIT', $b, $bob, 'securedField');

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'VIEW', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, 'EDIT', $a, 'securedField'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($alice, ['VIEW', 'EDIT'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($alice, 'MASTER', $a, 'foo'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($bob, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($bob, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($bob, ['EDIT', 'VIEW'], $a, 'securedField'));

        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($bob, 'MASTER', $a, 'foo'));
        $this->assertTrue($this->aclChecker->userIsGrantedOnObject($bob, 'EDIT', $b, 'securedField'));

        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'VIEW', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'EDIT', $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, ['EDIT', 'VIEW'], $a, 'securedField'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'MASTER', $a, 'foo'));
        $this->assertFalse($this->aclChecker->userIsGrantedOnObject($mallory, 'EDIT', $b, 'securedField'));
    }
}
