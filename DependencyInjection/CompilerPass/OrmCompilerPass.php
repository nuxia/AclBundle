<?php

namespace Nuxia\AclBundle\DependencyInjection\CompilerPass;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class OrmCompilerPass implements CompilerPassInterface
{
    /**
     * {@inheritdoc}
     */
    public function process(ContainerBuilder $container)
    {
        if (!$container->has('doctrine')) {
            return;
        }

        $aclFilterDef = $container->getDefinition('nuxia_acl.acl_filter');
        $aclFilterDef->addMethodCall('setAclWalker', ['Nuxia\AclBundle\Manager\AclWalker']);
    }
}
