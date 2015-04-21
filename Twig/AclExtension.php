<?php

namespace Nuxia\AclBundle\Twig;

use Nuxia\AclBundle\Manager\AclCheckerInterface;

class AclExtension extends \Twig_Extension
{
    /**
     * @var AclCheckerInterface
     */
    protected $aclChecker;

    /**
     * @param AclCheckerInterface $aclChecker
     */
    public function __construct(AclCheckerInterface $aclChecker)
    {
        $this->aclChecker = $aclChecker;
    }

    /**
     * {@inheritdoc}
     */
    public function getFunctions()
    {
        return [
            new \Twig_SimpleFunction('isGrantedOnClass', [$this->aclChecker, 'isGrantedOnClass']),
            new \Twig_SimpleFunction('isGrantedOnObject', [$this->aclChecker, 'isGrantedOnObject']),
            new \Twig_SimpleFunction('roleIsGrantedOnClass', [$this->aclChecker, 'roleIsGrantedOnClass']),
            new \Twig_SimpleFunction('roleIsGrantedOnObject', [$this->aclChecker, 'roleIsGrantedOnObject']),
            new \Twig_SimpleFunction('userIsGrantedOnClass', [$this->aclChecker, 'userIsGrantedOnClass']),
            new \Twig_SimpleFunction('userIsGrantedOnObject', [$this->aclChecker, 'userIsGrantedOnObject']),
        ];
    }
    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'nuxia_acl_acl';
    }
}
