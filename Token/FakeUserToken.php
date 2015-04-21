<?php

namespace Nuxia\AclBundle\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\Security\Core\User\UserInterface;

class FakeUserToken extends AbstractToken
{
    /**
     * @param UserInterface $user
     */
    public function __construct(UserInterface $user)
    {
        parent::__construct($user->getRoles());
        $this->setUser($user);
    }

    /**
     * {@inheritdoc}
     */
    public function getCredentials()
    {
        return '';
    }
}
