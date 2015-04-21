<?php

namespace Nuxia\AclBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('nuxia_acl');

        $rootNode
            ->children()
                ->scalarNode('permission_map_id')
                    ->defaultValue('security.acl.permission.map')
                    ->cannotBeEmpty()
                ->end()
                ->booleanNode('data_collector')
                    ->defaultValue(false)
                ->end()
            ->end();

        return $treeBuilder;
    }
}
