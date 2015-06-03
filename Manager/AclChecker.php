<?php

namespace Nuxia\AclBundle\Manager;

use Nuxia\AclBundle\Token\FakeRoleToken;
use Nuxia\AclBundle\Token\FakeUserToken;
use Symfony\Component\Security\Acl\Domain\ObjectIdentity;
use Symfony\Component\Security\Acl\Voter\FieldVote;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\RoleInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class AclChecker implements AclCheckerInterface
{
    /**
     * @var AclIdentifierInterface
     */
    protected $aclIdentifier;

    /**
     * @var AuthorizationCheckerInterface|SecurityContextInterface
     */
    protected $authorizationChecker;

    /**
     * @var AccessDecisionManagerInterface
     */
    protected $accessDecisionManager;

    /**
     * @param AclIdentifierInterface         $aclIdentifier
     * @param AuthorizationCheckerInterface|SecurityContextInterface       $authorizationChecker
     * @param AccessDecisionManagerInterface $accessDecisionManager
     */
    public function __construct(
        AclIdentifierInterface $aclIdentifier,
        $authorizationChecker,
        AccessDecisionManagerInterface $accessDecisionManager
    ) {
        if (!$authorizationChecker instanceof AuthorizationCheckerInterface && !$authorizationChecker instanceof SecurityContextInterface) {
            throw new \InvalidArgumentException('Argument 2 should be an instance of Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface or Symfony\Component\Security\Core\SecurityContextInterface');
        }

        $this->aclIdentifier = $aclIdentifier;
        $this->authorizationChecker = $authorizationChecker;
        $this->accessDecisionManager = $accessDecisionManager;
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnClass($attributes, $class, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function isGrantedOnObject($attributes, $object, $field = null)
    {
        return $this->authorizationChecker->isGranted(
            $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnClass($role, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function roleIsGrantedOnObject($role, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getRoleToken($role),
            (array) $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnClass($user, $attributes, $class, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_CLASS, $class, $field)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function userIsGrantedOnObject($user, $attributes, $object, $field = null)
    {
        return $this->accessDecisionManager->decide(
            $this->getUserToken($user),
            (array) $attributes,
            $this->getObjectToSecure(AclIdentifierInterface::OID_TYPE_OBJECT, $object, $field)
        );
    }

    /**
     * @param string        $type
     * @param string|object $classOrObject
     * @param null|string   $field
     *
     * @return ObjectIdentity|FieldVote
     */
    protected function getObjectToSecure($type, $classOrObject, $field = null)
    {
        $objectIdentity = $this->aclIdentifier->getObjectIdentity($type, $classOrObject);

        if (null === $field) {
            return $objectIdentity;
        }

        return new FieldVote($objectIdentity, $field);
    }

    /**
     * @param string|array|RoleInterface|TokenInterface $role
     *
     * @return FakeRoleToken|TokenInterface
     */
    protected function getRoleToken($role)
    {
        return $role instanceof TokenInterface ? $role :  new FakeRoleToken((array) $role);
    }

    /**
     * @param TokenInterface|UserInterface $user
     *
     * @return FakeUserToken
     * @throw \InvalidArgumentException
     */
    protected function getUserToken($user)
    {
        if ($user instanceof TokenInterface) {
            return $user;
        } elseif ($user instanceof UserInterface) {
            return new FakeUserToken($user);
        }

        throw new \InvalidArgumentException(sprintf(
            '$user must be instance of %s or %s',
            'Symfony\Component\Security\Core\Authentication\Token\TokenInterface',
            'Symfony\Component\Security\Core\User\UserInterface'
        ));
    }
}
