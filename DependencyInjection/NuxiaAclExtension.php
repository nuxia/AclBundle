<?php

namespace Nuxia\AclBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\HttpKernel\Kernel;

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

        // Set the SecurityContext for Symfony <2.6
        if (interface_exists('Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface')) {
            $tokenStorageReference = new Reference('security.token_storage');
            $authorizationCheckerReference = new Reference('security.authorization_checker');
        } else {
            $tokenStorageReference = new Reference('security.context');
            $authorizationCheckerReference = new Reference('security.context');
        }

        $container
            ->getDefinition('nuxia_acl.acl_identifier')
            ->replaceArgument(0, $tokenStorageReference);

        $container
            ->getDefinition('nuxia_acl.acl_checker')
            ->replaceArgument(1, $authorizationCheckerReference);

        $container
            ->getDefinition('nuxia_acl.acl_filter')
            ->replaceArgument(2, $tokenStorageReference);
    }
}
