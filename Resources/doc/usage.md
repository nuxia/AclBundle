# Usage

The two main services are :
- the AclManager (which grants and revokes access)
- the AclChecker (which takes the 'isGranted' decision)

## AclManager

```php
$aclManager = $container->get('nuxia_acl.acl_manager');
```

The AclManager can grant (or revoke) a Role (or a User) on a Class (or an Object).
This gives 8 combinations exposed as 8 methods in the AclManager :

```php
AclManager::grantRoleOnClass($permissions, $class, $role, $field = null)
AclManager::grantRoleOnObject($permissions, $object, $role, $field = null)
AclManager::grantUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
AclManager::grantUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
AclManager::revokeRoleOnClass($permissions, $class, $role, $field = null)
AclManager::revokeRoleOnObject($permissions, $object, $role, $field = null)
AclManager::revokeUserOnClass($permissions, $class, UserInterface $user = null, $field = null)
AclManager::revokeUserOnObject($permissions, $object, UserInterface $user = null, $field = null)
```

* The '$permissions' argument si the permission(s) we want to act on. It will refer to the MaskBuilder used in the PermissionMap.
* The '$class' argument is the string representation of the class we want to secure (the ObjectIdentity). It also accepts an object as argument and it will be converted to a string with get_class().
* The '$object' argument is the specific object we want to secure (the ObjectIdentity). This object must have a 'getId' method or implement [DomainObjectInterface](https://github.com/symfony/symfony/blob/2.7/src/Symfony/Component/Security/Acl/Model/DomainObjectInterface.php)
* The '$role' argument is the role that will be affected (the SecurityIdentity). A string or a [Role](https://github.com/symfony/symfony/blob/2.7/src/Symfony/Component/Security/Core/Role/Role.php) instance.
* The 'UserInterface $user = null' is the user that will be affected (the SecurityIdentity). If null, it will catch the current authenticated User or Token.
* The '$field = null' : if not null, the process will be effective on a [field-based ACE](https://github.com/symfony/symfony/blob/2.7/src/Symfony/Component/Security/Acl/Model/MutableAclInterface.php)

Examples :

```php
$aclManager->grantRoleOnClass('VIEW', 'MyBundle\Entity\Post', 'ROLE_USER');
$aclManager->grantUserOnObject('EDIT', $post, $user);
```

## AclChecker

```php
$aclChecker = $container->get('nuxia_acl.acl_checker');
```

The AclChecker gets the 'isGranted' decision.

```php
if ($aclChecker->isGrantedOnClass('VIEW', 'MyBundle\Entity\Post')) {
    // The current user can VIEW the class MyBundle\Entity\Post
}
if ($aclChecker->isGrantedOnObject('EDIT', $post)) {
    // The current user can EDIT object $post
}

if ($aclChecker->roleIsGrantedOnClass('ROLE_USER', 'VIEW', 'MyBundle\Entity\Post')) {
    // The role ROLE_USER can VIEW the class MyBundle\Entity\Post
}
if ($aclChecker->roleIsGrantedOnObject('ROLE_ADMIN', 'EDIT', $post)) {
    // The role ROLE_ADMIN can EDIT the object $post
}

if ($aclChecker->userIsGrantedOnClass($alice, 'VIEW', 'MyBundle\Entity\Post')) {
    // The user $alice can VIEW the class MyBundle\Entity\Post
}
if ($aclChecker->userIsGrantedOnObject($bob, 'EDIT', $post)) {
    // The user $bob can EDIT the object $post
}
```

## AclFilter

```php
$aclFilter = $container->get('nuxia_acl.acl_filter');
```

The AclFilter helps retrieving only granted objects.

```php
$queryBuilder = $repository->getQueryBuilder();
$query = $aclFilter->apply($queryBuilder, 'VIEW', 'Post', 'p.id');
$posts = $query->getResult();
// The current user will only see the posts he is granted on with the VIEW permission
```
