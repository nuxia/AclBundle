<?php

use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;

class AppKernel extends Kernel
{
    public function registerBundles()
    {
        $bundles = array(
            new Symfony\Bundle\FrameworkBundle\FrameworkBundle(),
            new Symfony\Bundle\SecurityBundle\SecurityBundle(),
            new Doctrine\Bundle\DoctrineBundle\DoctrineBundle(),
            new Nuxia\AclBundle\NuxiaAclBundle(),
        );

        return $bundles;
    }

    public function registerContainerConfiguration(LoaderInterface $loader)
    {
        $loader->load(__DIR__.'/config/config.yml');
        $loader->load(function (\Symfony\Component\DependencyInjection\ContainerBuilder $container) {
            if (!isset($GLOBALS['db_type']) || 'pdo_sqlite' === $GLOBALS['db_type']) {
                $connection = array(
                    'driver' => 'pdo_sqlite',
                    'memory' => true,
                );
            } else {
                $connection = array(
                    'driver' => $GLOBALS['db_type'],
                    'host' => $GLOBALS['db_host'],
                    'port' => $GLOBALS['db_port'],
                    'dbname' => $GLOBALS['db_name'],
                    'user' => $GLOBALS['db_username'],
                    'password' => $GLOBALS['db_password'],
                );
            }

            $container->loadFromExtension('doctrine', array(
                'dbal' => array(
                    'default_connection' => 'default',
                    'connections' => array(
                        'default' => $connection
                    )
                )
            ));
        });
    }
}
