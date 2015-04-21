# Configuration

## Symony ACL Component

First, configure the ACL Symfony system : [Symfony ACL Cookbook](http://symfony.com/doc/current/cookbook/security/acl.html)

```yml
# app/config/security.yml
security:
    acl:
        connection: default
```

```bash
$ php app/console init:acl
```

Don't forget to check the allow_if_object_identity_unavailable parameter.
In most situations, you'll want it to be false, but its default value is true. 

```yml
# app/config/security.yml
security:
    acl:
        connection: default
        voter:
            allow_if_object_identity_unavailable: false
```

## AclBundle

If you defined a [custom PermissionMap](#) and its service id is different than the default one (security.acl.permission.map) :

```yml
# app/config.yml
nuxia_acl:
    permission_map_id: your_permission_map
```

## Next step

[Usage](usage.md)
