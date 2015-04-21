<?php

namespace Nuxia\AclBundle;

use Nuxia\AclBundle\DependencyInjection\CompilerPass\OrmCompilerPass;
use Nuxia\AclBundle\DependencyInjection\CompilerPass\TwigCompilerPass;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class NuxiaAclBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        $container->addCompilerPass(new OrmCompilerPass());
        $container->addCompilerPass(new TwigCompilerPass());
    }
}
