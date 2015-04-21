<?php

namespace Nuxia\AclBundle\DataCollector;

use Nuxia\AclBundle\DataCollector\Collector\AclCheckerCollector;
use Nuxia\AclBundle\DataCollector\Collector\AclFilterCollector;
use Nuxia\AclBundle\DataCollector\Collector\AclManagerCollector;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Symfony\Component\HttpKernel\DataCollector\LateDataCollectorInterface;

class AclDataCollector extends DataCollector implements LateDataCollectorInterface
{
    /**
     * @var AclCheckerCollector
     */
    protected $aclCheckerCollector;

    /**
     * @var AclManagerCollector
     */
    protected $aclManagerCollector;

    /**
     * @var AclFilterCollector
     */
    protected $aclFilterCollector;

    /**
     * @param AclCheckerCollector $aclCheckerCollector
     * @param AclManagerCollector $aclManagerCollector
     * @param AclFilterCollector  $aclFilterCollector
     */
    public function __construct(
        AclCheckerCollector $aclCheckerCollector,
        AclManagerCollector $aclManagerCollector,
        AclFilterCollector $aclFilterCollector
    ) {
        $this->aclCheckerCollector = $aclCheckerCollector;
        $this->aclManagerCollector = $aclManagerCollector;
        $this->aclFilterCollector = $aclFilterCollector;
    }

    /**
     * {@inheritdoc}
     */
    public function collect(Request $request, Response $response, \Exception $exception = null)
    {

    }

    /**
     * {@inheritdoc}
     */
    public function lateCollect()
    {
        $checks = new \ReflectionProperty('Nuxia\AclBundle\DataCollector\Collector\AclCheckerCollector', 'checks');
        $checks->setAccessible(true);
        $this->data['checks'] = $checks->getValue($this->aclCheckerCollector);

        $managements = new \ReflectionProperty('Nuxia\AclBundle\DataCollector\Collector\AclManagerCollector', 'managements');
        $managements->setAccessible(true);
        $this->data['managements'] = $managements->getValue($this->aclManagerCollector);

        $filters = new \ReflectionProperty('Nuxia\AclBundle\DataCollector\Collector\AclFilterCollector', 'filters');
        $filters->setAccessible(true);
        $this->data['filters'] = $filters->getValue($this->aclFilterCollector);
    }

    /**
     * @return int
     */
    public function getCount()
    {
        return
            count($this->getChecks())
            + count($this->getManagements())
            + count($this->getFilters());
    }

    /**
     * @return float
     */
    public function getTime()
    {
        return
            $this->getChecksTime()
            + $this->getManagementsTime()
            + $this->getFiltersTime();
    }

    /**
     * @return array
     */
    public function getChecks()
    {
        return isset($this->data['checks']) ? $this->data['checks'] : [];
    }

    /**
     * @return float
     */
    public function getChecksTime()
    {
        $time = 0;
        foreach ($this->getChecks() as $check) {
            $time += $check['time'];
        }

        return round($time, 2);
    }

    /**
     * @return array
     */
    public function getManagements()
    {
        return isset($this->data['managements']) ? $this->data['managements'] : [];
    }

    /**
     * @return float
     */
    public function getManagementsTime()
    {
        $time = 0;
        foreach ($this->getManagements() as $management) {
            $time += $management['time'];
        }

        return round($time, 2);
    }

    /**
     * @return array
     */
    public function getFilters()
    {
        return isset($this->data['filters']) ? $this->data['filters'] : [];
    }

    /**
     * @return float
     */
    public function getFiltersTime()
    {
        $time = 0;
        foreach ($this->getFilters() as $filter) {
            $time += $filter['time'];
        }

        return round($time, 2);
    }

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return 'acl';
    }

}
