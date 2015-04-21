<?php

namespace Nuxia\AclBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

class NuxiaAclExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        $container->setAlias('nuxia_acl.permission_map', $config['permission_map_id']);

        //Decorated services are only supported since symfony 2.5
        if (true === $config['data_collector'] && method_exists(
            'Symfony\Component\DependencyInjection\Definition',
            'setDecoratedService'
        )) {
            $loader->load('collectors.yml');
        }
    }
}
