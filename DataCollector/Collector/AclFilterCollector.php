<?php

namespace Nuxia\AclBundle\DataCollector\Collector;

use Nuxia\AclBundle\Manager\AclFilterInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Stopwatch\Stopwatch;

class AclFilterCollector implements AclFilterInterface
{
    /**
     * @var AclFilterInterface
     */
    private $aclFilter;

    /**
     * @var Stopwatch
     */
    private $stopwatch;

    /**
     * @var array
     */
    private $filters;

    /**
     * @param AclFilterInterface $aclFilter
     * @param Stopwatch          $stopwatch
     */
    public function __construct(AclFilterInterface $aclFilter, Stopwatch $stopwatch)
    {
        $this->aclFilter = $aclFilter;
        $this->stopwatch = $stopwatch;
        $this->filters = [];
    }

    /**
     * @param string $function
     * @param array  $arguments
     *
     * @return mixed
     */
    private function collectFilter($function, $arguments)
    {
        $this->stopwatch->start('acl.filters');

        $result = call_user_func_array([$this->aclFilter, $function], $arguments);

        $periods = $this->stopwatch->stop('acl.filters')->getPeriods();

        $this->filters[] = [
            'method' => $function,
            'query' => $result->getSQL(),
            'time' => end($periods)->getDuration()
        ];

        return $result;
    }

    /**
     * {@inheritdoc}
     */
    public function apply(
        $queryBuilder,
        $permission,
        $oidClass,
        $oidReference,
        UserInterface $user = null,
        array $orX = []
    ) {
        return $this->collectFilter(__FUNCTION__, func_get_args());
    }

    /**
     * @param $method
     * @param $arguments
     * @return mixed
     */
    public function __call($method, $arguments)
    {
        return call_user_func_array([$this->aclFilter, $method], $arguments);
    }
}
