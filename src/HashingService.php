<?php

namespace devtoolboxuk\hashing;

class HashingService
{

    const HMAC = 'hmac';
    const OTHER = 'normal';

    const SHA256 = 'sha256';
    const SHA384 = 'sha384';
    const SHA512 = 'sha512';
    const MD5 = 'md5';

    protected $algorithm = 'sha256';
    protected $hashFunction = 'hmac';
    private $hashingKey;
    private $hashedData;

    public function hash($data)
    {

        switch ($this->getHashFunction()) {
            case self::HMAC:
                $data = base64_encode(hash_hmac($this->getAlgorithm(), $data, $this->getHashingKey(), true));
                break;
            default:
                $ctx = hash_init($this->getAlgorithm());
                hash_update($ctx, $data);
                $data = hash_final($ctx, false);
                break;
        }

        $this->setHashedData($data);
    }

    public function getHashFunction()
    {
        return $this->hashFunction;
    }

    public function setHashFunction($type = self::HMAC)
    {
        switch ($type) {
            case self::HMAC:
                $this->hashFunction = self::HMAC;
                break;
            default:
                $this->hashFunction = self::OTHER;
                break;
        }
    }

    public function getAlgorithm()
    {
        return $this->algorithm;
    }

    public function setAlgorithm($type = 'sha256')
    {

        switch ($type) {
            case self::MD5:
                $this->algorithm = self::MD5;
                break;

            case self::SHA384:
                $this->algorithm = self::SHA384;
                break;

            case self::SHA512:
                $this->algorithm = self::SHA512;
                break;

            case self::SHA256:
            default:
                $this->algorithm = self::SHA256;
                break;
        }
    }

    public function getHashingKey()
    {
        return $this->hashingKey;
    }

    public function setHashingKey($hashing_key)
    {
        $this->hashingKey = $hashing_key;
    }

    private function setHashedData($data)
    {
        $this->hashedData = $data;
    }

    public function getHashedData()
    {
        return $this->hashedData;
    }
}