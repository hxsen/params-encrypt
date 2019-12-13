<?php

namespace Hxsen\ParamsEncrypt;;

class TokenController
{
    // 用户需要加密的地址参数
    private $params = [];
    private $config = [];
    private $values = [];

        // 单例函数的实例化
    private static $instance;

    private static function getInstance(){
        if(!self::$instance){
            self::$instance = new self();
        }
        return self::$instance;
    }
    // 实例化
    private function __construct()
    {
        $this->config = [
            'key' => 'a071495b74b65a34559c76227e0633a4',
            'userId' => '1',
        ];
    }

    // 制作加密的数据
    public static function build(array $params){
        return self::getInstance()->init($params)->makeSign();
    }
    // 验证加密数据
    public static function check(array $params){
        return self::getInstance()->init($params)->checkSign();
    }
    // 初始化数据
    private function init($params){
        $this->params = $params;
        // 如果有传递签名就记录用户的签名
        if($this->haveSign()) $this->setUserSign($this->params['sign']);
        return $this;
    }
    /**
     * @param WxPayConfigInterface $config  配置对象
     * 检测签名
     */
    public function checkSign()
    {
        // 检测参数是否存在签名
        if(!$this->haveSign()){
            throw new \Exception("签名错误！");
        }
        // 建立新的签名
        $sign = $this->makeSign();
        if($this->getUserSign() == $sign){
            //签名正确
            return true;
        }
        return false;
    }
    /**
     * 判断签名，详见签名生成算法是否存在
     * @return true 或 false
     **/
    private function haveSign()
    {
        return array_key_exists('sign', $this->params);
    }
    /**
     * 设置签名方式
     * @param string $value
     **/
    private function setUserSign($value)
    {
        $this->values['userSign'] = $value;
    }
    /**
     * 获取签名方式
     **/
    private function getUserSign()
    {
        return isset($this->values['userSign']) ? $this->values['userSign'] : '';
    }
    /**
     * 格式化参数格式化成url参数
     */
    private function toUrlParams()
    {
        $buff = "";
        foreach ($this->params as $k => $v)
        {
            if($k != "sign" && $v != "" && !is_array($v)){
                $buff .= $k . "=" . $v . "&";
            }
        }

        $buff = trim($buff, "&");
        return $buff;
    }
    /**
     * 生成签名 - 重写该方法
     * @param WxPayConfigInterface $config  配置对象
     * @param bool $needSignType  是否需要补signtype
     * @return 签名，本函数不覆盖sign成员变量，如要设置签名需要调用SetSign方法赋值
     */
    public function makeSign()
    {
        //签名步骤一：按字典序排序参数
        ksort($this->params);
        $string = $this->toUrlParams();
        //签名步骤二：在string后加入KEY
        $string = $string . "&key=".$this->config['key'];
        //签名步骤三：MD5加密或者HMAC-SHA256
        if(strlen($this->getUserSign()) <= 32){
            //如果签名小于等于32个,则使用md5验证
            $string = md5($string);
        } else {
            //是用sha256校验
            $string = hash_hmac("sha256", $string, $this->config['key']);
        }
        //签名步骤四：所有字符转为大写
        $result = strtoupper($string);
        return $result;
    }
}
