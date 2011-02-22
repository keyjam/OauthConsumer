<?php
/** 
 * GreePlatform Oauth
 * FeaturePhone
 * @author Kazuki Endo
 * @description このモジュールはGREEのみ検証済みです。随時その他のOauth認証にて検証していきます。
 * @virsion 0.0.1
 **/

/*
	Class KeyOauth Start
*/
class keyOauth {

	/**
	 * メンバー変数
	 * 
	 **/
	public $key		 = ''; //コンシューマキー
	public $secret	 = ''; //コンシューマシークレット

	/**
	 * コンストラクタ
	 * 
	 **/
	function __construct( $key, $secret ) {
		$this->key = $key;
		$this->secret = $secret;
	}

	/**
	 * オブジェクトの情報を定義
	 * 
	**/
	function __toString() {
		return "checkOauth[key=$this->key,secret=$this->secret]";
	}

}

/*
	Class OauthRequest Start
*/
class OauthRequest {

	/**
	 * メンバー変数
	 * 
	 **/
	protected $param	 = '';
	protected $method	 = '';
	protected $url		 = '';
	protected $body		 = '';
	public $base_string	 = '';

	/**
	 * コンストラクタ
	 * 
	 **/
	function __construct( $method, $url, $param = '', $body = '') {
		deBug("[Oauth body ] : ".print_r($body,1)); 

		$param			 = ($param) ? $param : array();
		$body			 = ($body) ? $body : array();
		$param			 = array_merge( $this->parse_parameters(parse_url($http_url, PHP_URL_QUERY)), $param);
		$this->param	 = $param;
		$this->method	 = $method;
		$this->url		 = $url;
		$this->body		 = $body;

	}

	/**
	 * 初期値セット
	 * 
	 **/
	public function set( $consumer, $method, $url, $param = '', $body = '' ) {

		$body = ($body) ? $body : array();
		$param = ($param) ?  $param : array();
		$defaults = array("oauth_consumer_key" => $consumer->key);
		$param = array_merge($defaults, $param);
		return new OauthRequest($method, $url, $param, $body);
	}

	/**
	 * 暗号化キーの作成
	 * HMAC-SHA1
	 **/
	public function createSignature( $consumer, $token = '' ) {

		$base_string = $this->createBaseString();
		$this->base_string = $base_string;

		deBug("[Oauth base_string ] : ".print_r($base_string,1)); 
		deBug("[Oauth consumer ] : ".print_r($consumer,1)); 
		deBug("[Oauth token ] : ".print_r($token,1)); 

		$key_parts = array(
			$consumer->secret, $token
		);

		//$key_parts = rawurlencode($key_parts);
		$key = implode('&', $key_parts);

		deBug("[Oauth Key ] : ".print_r($key,1)); 
		deBug("[Oauth Create Signature ] : ".base64_encode(hash_hmac('sha1', $base_string, $key, true))); 

		$signature =  base64_encode(hash_hmac('sha1', $base_string, $key, true));

		$this->set_parameter("oauth_signature", $signature, false);

	}

	/**
	 * BaseString 生成
	 * 
	 **/
	public function createBaseString() {

		// 各データの生成
		$sigBase 	= array();
		$sigBase[]	= $this->getMethod();
		$sigBase[]	= $this->getUrl();
		$sigBase[]	= $this->getParams();

		return implode('&', array_map('rawurlencode', $sigBase));

	}

	/**
	 * Methodセット
	 * 
	 **/
	public function getMethod() {
		return strtoupper($this->method);
	}

	/**
	 * Urlセット
	 * 
	 **/
	public function getUrl() {

		$parts = parse_url($this->url);

		$scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
		$port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
		$host = (isset($parts['host'])) ? $parts['host'] : '';
		$path = (isset($parts['path'])) ? $parts['path'] : '';

		if (($scheme == 'https' && $port != '443') || ($scheme == 'http' && $port != '80')) {
			$host = "$host:$port";
		}
		return "$scheme://$host$path";
	}

	/**
	 * Parameter情報取得
	 * 
	 **/
	public function getParams() {

		$params = $this->param;

		// BaseStringにはsignatureは含めない
		if (isset($params['oauth_signature'])) {
		unset($params['oauth_signature']);
		}

		return $this->build_http_query($params);

	}

	/**
	 * Parameterセット
	 * 
	 **/
	public function set_parameter($name, $value, $allow_duplicates = true) {

		if ($allow_duplicates && isset($this->param[$name])) {

			// array or obj or resurceの場合
			if (is_scalar($this->param[$name])) {

				$this->param[$name] = array($this->param[$name]);
			}

			$this->param[$name][] = $value;
		} else {
			$this->param[$name] = $value;
		}
	}

	/**
	 * Build http query
	 * 
	 **/
	public function build_http_query($params) {

		if (!$params) return '';

//		uksort($params, 'strcmp');

		$normalized = array();
		ksort($params);
		foreach ($params as $key => $value) {

			$normalized[] = $key.'='.$value;

		}

		return implode('&', $normalized);
	}

	/**
	 * Query解析
	 * 
	 **/
	public static function parse_parameters( $input ) {

		if (!isset($input) || !$input) return array();

		$pairs = explode('&', $input);
		$parsed_parameters = array();
		foreach ($pairs as $pair) {
			$split = explode('=', $pair, 2);
			//$parameter = OAuthUtil::urldecode_rfc3986($split[0]);
			$parameter = $split[0];
			$value = isset($split[1]) ? $split[1] : '';

			if (isset($parsed_parameters[$parameter])) {

				if (is_scalar($parsed_parameters[$parameter])) {

					$parsed_parameters[$parameter] = array($parsed_parameters[$parameter]);
				}

				$parsed_parameters[$parameter][] = $value;

			} else {
				$parsed_parameters[$parameter] = $value;
			}
		}
		return $parsed_parameters;
	}

	/**
	 * exec Curl
	 * @retrun API DATA like POST or GET
	 **/
	public function execCurl() {

		deBug("[Exec Curl ] : ".print_r($this,1)); 

		$curl 		= curl_init();
		$method		= $this->getMethod();
		$url		= $this->getUrl();
		$header[]	= $this->getAuthorization();
		$query		= $this->getParams();
		$body		= $this->body;

		if ($method == 'POST') {
			if (!$has_content_type) {
				$header[]			 = 'Content-Type: application/json';
			}

			curl_setopt($curl, CURLOPT_POST, 		 true);
			curl_setopt($curl, CURLOPT_POSTFIELDS,	 $body);

		} else {

			if (!empty($query))
			{
				$url .= '?'.$query;
			}
			if ($method != 'GET')
			{
				curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
			}
		}

		curl_setopt($curl, CURLOPT_URL, 			 $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER,	 true);
		curl_setopt($curl, CURLOPT_FAILONERROR,		 false);
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER,	 false);
		curl_setopt($curl, CURLOPT_TIMEOUT, 		 30);
		curl_setopt($curl, CURLOPT_HTTPHEADER,		 $header);

		deBug("[Chack auth_header ] : ".print_r($header,1)); 

		$response = curl_exec($curl);
		if ($response === false) {
			$error = curl_error($curl);
			curl_close($curl);
			throw new OAuthException2('CURL error: ' . $error);
		} 
		$status = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		deBug("[bkapp response ] : ".print_r($status,1)); 
		curl_close($curl);
		deBug("[bkapp response ] : ".print_r($response,1)); 

		return $response;
	}

	/**
	 * Build Authorization Header
	 * 
	 **/
	function getAuthorization() {

		$h   = array();
		$h[] = 'Authorization: OAuth ';

		foreach ($this->param as $name => $value)
		{
			// 特定のキーのみ値をセット
			if (strncmp($name, 'oauth_', 6) == 0 || strncmp($name, 'xoauth_', 7) == 0)
			{
				$h[] = $name.'="'.$value.'"';
			}
		}

		$hs = implode(', ', $h);
		return $hs;
	}

}

//デバッグ用
function deBug($value) {
	$fh=fopen("/home/webadmin/dev_www/html/logs/".date("Ymd").".log","a");
	fwrite($fh,date("Y/m/d H:i:s")."\t".$_SERVER['SCRIPT_NAME']."\t".$value."\n");
	fclose($fh);
}

