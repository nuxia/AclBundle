<?php

namespace Nuxia\AclBundle\Tests\Model;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Table;

/**
 * @Entity
 * @Table(name="posts")
 *
 */
class PostObject
{
    /**
     * @Id
     * @Column(type="integer")
     *
     * @var int
     */
    protected $id;

    /**
     * @Column(type="string")
     *
     * @var string
     */
    protected $status;

    /**
     * @param int $id
     */
    public function __construct($id)
    {
        $this->id = $id;
        $this->status = 0 === $id % 2 ? 'even' : 'odd';
    }

    /**
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $status
     *
     * @return PostObject
     */
    public function setStatus($status)
    {
        $this->status = $status;

        return $this;
    }

    /**
     * @return string
     */
    public function getStatus()
    {
        return $this->status;
    }
}
