<?php

require_once 'src/HashingService.php';

class hashing extends TestCase
{

    protected $hashingService;
    protected $hashingKey;
    protected $functions = ['hmac', 'normal'];
    protected $algorithms = ['sha256', 'sha384', 'sha512', 'md5'];
    protected $testData = 'I am some test data';

    function __construct($name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        $this->hashingService = new HashingService();
    }

    public function testBasicHashing()
    {

        $this->setHashingKey('testingkey');
        $this->assertSame('testingkey', $this->hashingKey);
        $this->assertNotSame('testingkeyother', $this->hashingKey);

        $this->assertSame('sha256', $this->hashingService->getAlgorithm());
        $this->assertSame('hmac', $this->hashingService->getHashFunction());

        $this->hashingService->hash($this->testData);
        $this->assertSame('cEmya4XLJPT9fuOXlmTN3LQ9a3DOwQTuNzdDAJ/8sLs=', $this->hashingService->getHashedData());

    }

    /**
     * @param string $key
     */
    private function setHashingKey($key)
    {
        $this->hashingService->setHashingKey($key);
        $this->hashingKey = $this->hashingService->getHashingKey();
    }

    public function testChangingHashingKey()
    {
        $this->setHashingKey('testingkeyNew');
        $this->assertSame('testingkeyNew', $this->hashingKey);
        $this->assertNotSame('testingkey', $this->hashingKey);


    }

    public function testChangingAlgorithm()
    {

        foreach ($this->algorithms as $algorithm) {
            $this->hashingService->setAlgorithm($algorithm);
            $this->assertSame($algorithm, $this->hashingService->getAlgorithm());
        }

    }

    public function testChangingHashingFunction()
    {

        foreach ($this->functions as $function) {
            $this->hashingService->setHashFunction($function);
            $this->assertSame($function, $this->hashingService->getHashFunction());
        }

    }

    public function testHashingDataUsingMd5AndHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('md5');

        $this->hashingService->setHashFunction('hmac');
        $this->hashingService->hash($this->testData);
        $this->assertSame('+UICT0xJZEuGYJA+jzlWcA==', $this->hashingService->getHashedData());

    }

    public function testHashingDataUsingMd5AndNotHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('md5');

        $this->hashingService->setHashFunction('normal');
        $this->hashingService->hash($this->testData);
        $this->assertSame('3da0e28c2d29595d3e172f00f180c1db', $this->hashingService->getHashedData());

    }

    public function testHashingDataUsingSHA256AndHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha256');

        $this->hashingService->setHashFunction('hmac');
        $this->hashingService->hash($this->testData);
        $this->assertSame('cEmya4XLJPT9fuOXlmTN3LQ9a3DOwQTuNzdDAJ/8sLs=', $this->hashingService->getHashedData());
    }

    public function testHashingDataUsingSHA256AndNotHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha256');

        $this->hashingService->setHashFunction('normal');
        $this->hashingService->hash($this->testData);
        $this->assertSame('33968f66ba0822473dab4552cb42c489a0fb869691ac92e72fe8e734d1dfb077',
            $this->hashingService->getHashedData());
    }

    public function testHashingDataUsingSHA384AndHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha384');

        $this->hashingService->setHashFunction('hmac');
        $this->hashingService->hash($this->testData);
        $this->assertSame('XAaFQ8X5n83ccNRd9Eo13VOm4xvZs8amZwCTPQ2FJ4XtfTIDt7f7esI/POzUYRIF',
            $this->hashingService->getHashedData());
    }

    public function testHashingDataUsingSHA384AndNotHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha384');

        $this->hashingService->setHashFunction('normal');
        $this->hashingService->hash($this->testData);
        $this->assertSame('2f5f523a2d89e5de95a6d4437f6a32cd27562504fd5a4e67ec0d2181fbadfb178ddd3b2890e63afa76a411ac8dd45b71',
            $this->hashingService->getHashedData());
    }


    public function testHashingDataUsingSHA512AndHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha512');

        $this->hashingService->setHashFunction('hmac');
        $this->hashingService->hash($this->testData);
        $this->assertSame('LW8fNBERTBL1Apy3i7TLBvejYmeFjqLLo2Q6woiPajyxT4xU/GwuqS3bfNmG1Ld5PQmTLvgkIaPXSLkfGj1vbQ==',
            $this->hashingService->getHashedData());

    }

    public function testHashingDataUsingSHA512AndNotHmac()
    {
        $this->setHashingKey('testingkey');
        $this->hashingService->setAlgorithm('sha512');

        $this->hashingService->setHashFunction('normal');
        $this->hashingService->hash($this->testData);
        $this->assertSame('afb58a348d3d9289ed045349f965621cfd48920b0517e3bb3691cd7229c5cab003d3c3e7351243eefd353b08dca7b14023c5c282fc1df2b8baea33843efd4c7d',
            $this->hashingService->getHashedData());

    }

}
