<?php
namespace Smbbk\Id\Linkaja;

class Linkaja {
	const api_url 					= 'https://linkaja.btmsdigital.com';
    const os_name 					= 'iOS';
    const os_version 				= '14.4.2';
    const app_id 					= 'P72RVSPSF61F72ELYLZI';
    const app_version 				= '3.37.0';
    const user_agent 				= 'Linkaja/16820 Skywalker/1.0 with CFNetwork/1220.1 Darwin/20.3.0';
    const action_mark 				= 'Linkaja Wallet';
	const client_id					= "linkaja_ios";
	const app_authentication		= 'aWYgKCRjb2xsZWN0RGF0YVsndmlld190eXBlJ10gPT0gJ2FjdGlvbicpIHs';
	/*
    @ Push Notification ID (SHA256 Hash)
    @ Generated from self::generateRandomSHA256();
    */
    
	const clientCountryPhone		= '+62';
	const clientCountryCode 		= 'ID';
	
	/*
    @ Device ID (UUIDV4)
    @ Generated from self::generateUUIDV4();
    */
	private $device_id				= '';
	private $push_notif_id 			= '';

	private static $api_consumer 	= 'customer';
	private $headers 				= array();
	protected $cookies_path			= '';
	protected $acc_num				= '';
	private $curl_options			= [
		'timedout_execution'				=> 30,
		'timedout_connect'					=> 15,
		'user_agent'						=> '',
	];
	protected $ch					= null;
	protected $curl_collect			= [
		'error_code'						=> 0,
		'error_msg'							=> '',
	];
	
    private $authToken, $uniqueId, $sessionId, $pin, $idKey;
	private static $transfer_action_mark = [
		'ovo'			=> 'trf_linkaja',
		'bank'			=> 'trf_other_bank',
		'cash_wallet'	=> 'Linkaja Cash',
		'cash_bank'		=> 'Linkaja Cash',
	];
	private static $transfer_minimum = [
		'wallet'		=> 10000,
		'linkaja'		=> 10000,
		'bank'			=> 10000,
	];
	
	public function __construct($acc_num, $cookie_path = '') {
		$this->acc_num = ((is_string($acc_num) || is_numeric($acc_num)) ? sprintf("%s", $acc_num) : '');
		if (strlen($this->acc_num) == 0) {
			return false;
		}
		$this->set_header_auth();
		$this->curl_options['user_agent'] = self::user_agent;
		$this->cookies_path = $cookie_path;
    }
	private function set_uuidv4($input_params) {
		if (!isset($input_params['sessionId']) && !isset($input_params['uniqueId'])) {
			return;
		}
		$this->sessionId = $input_params['sessionId'];
        $this->uniqueId = $input_params['uniqueId'];
	}
	private function uuidv4() {
        $data    = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4)));
    }
	public function generate_random_sha256() {
		return hash_hmac('sha256', microtime(), substr(md5(sprintf("%s%s", time(), uniqid())), 0, 16));
	}
	public function generate_uuidv4() {
		return $this->uuidv4();
	}
	private function set_header_auth() {
		$this->headers = array(
			'Content-Type'			=> 'application/x-www-form-urlencoded',
			'App-Id'				=> self::app_id,
			'App-Version'			=> self::app_version,
			'Os'					=> self::os_name,
			'Os-Version'			=> self::os_version,
			'User-Agent'			=> self::user_agent,
			'Authentication'		=> 'Bearer ' . self::app_authentication,
        );
        return $this->headers;
	}
	public function set_device_id(String $device_id) {
		$this->device_id = $device_id;
	}
	public function set_push_notif_id(String $push_notif_id) {
		$this->push_notif_id = $push_notif_id;
	}
	
	private function set_authorization($token = '') {
		$token = (is_string($token) ? sprintf("%s", $token) : '');
		if (strlen($token) == 0) {
			return false;
		}
		$this->authToken = $token;
		$this->headers['X-Api-Authorization'] = sprintf("%s", $this->authToken);
		$this->headers['Os-Version'] = sprintf("%s", self::os_version);
		$this->headers['Client-Id'] = sprintf("%s", self::client_id);
		return $this->headers;
	}
	
	//----
	// CURL Instances
	//----
	private function set_curl_init($url_hostname, $headers = null) {
		$this->ch = curl_init();
		curl_setopt($this->ch, CURLOPT_URL, $url_hostname);
		curl_setopt($this->ch, CURLOPT_VERBOSE, TRUE);
		//curl_setopt($this->ch, CURLOPT_COOKIELIST, TRUE);
		//curl_setopt($this->ch, CURLOPT_FAILONERROR, TRUE);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYHOST, 2);
		curl_setopt($this->ch, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($this->ch, CURLOPT_SSLVERSION, 6);
		curl_setopt($this->ch, CURLOPT_COOKIESESSION, TRUE);
		
		//curl_setopt($this->ch, CURLOPT_COOKIEFILE, ($this->cookies_path . DIRECTORY_SEPARATOR . "{$this->acc_num}.log"));
		//curl_setopt($this->ch, CURLOPT_COOKIEJAR, ($this->cookies_path . DIRECTORY_SEPARATOR . "{$this->acc_num}.log"));
		curl_setopt($this->ch, CURLOPT_HEADER, FALSE);
		if (isset($headers)) {
			curl_setopt($this->ch, CURLOPT_HTTPHEADER, $headers);
		}
		curl_setopt($this->ch, CURLOPT_CONNECTTIMEOUT, $this->curl_options['timedout_connect']);
		curl_setopt($this->ch, CURLOPT_TIMEOUT, $this->curl_options['timedout_execution']);
		curl_setopt($this->ch, CURLOPT_USERAGENT, $this->curl_options['user_agent']);
		curl_setopt($this->ch, CURLOPT_ENCODING, "");
		curl_setopt($this->ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($this->ch, CURLOPT_AUTOREFERER, true);
		
		return $this->ch;
	}
	private function curlexec() {
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, TRUE);
		$this->curl_collect['error_code'] = 0;
		$this->curl_collect['error_msg'] = '';
		
		try {
			$this->curl_collect['http_body'] = curl_exec($this->ch);
		} catch (Exception $ex) {
			throw $ex;
			$this->curl_collect['http_body'] = FALSE;
		}
		$this->curl_collect['http_code'] = curl_getinfo($this->ch, CURLINFO_HTTP_CODE);
		if (curl_error($this->ch)) {
			$this->curl_collect['error_code'] = curl_errno($this->ch);
			$this->curl_collect['error_msg'] = curl_error($this->ch);
		}
		curl_close($this->ch);
		
        return $this->curl_collect;
    }
	public function generate_curl_headers($headers = null) {
		if (!isset($headers)) {
			$headers = $this->headers;
		}
		return $this->create_curl_headers($headers);
	}
	private function create_curl_headers($headers = array()) {
		$headers_curl = array();
		if (is_array($headers) && (count($headers) > 0)) {
			foreach ($headers as $hkey => $hval) {
				$headers_curl[] = sprintf("%s: %s", $hkey, $hval);
			}
		}
		return $headers_curl;
	}
	private function set_headers($headers = array()) {
		$this->headers = $headers;
		return $this;
	}
	public function reset_headers() {
		$this->headers = null;
		return $this;
	}
	public function get_curl_instance_created() {
		return $this->curl;
	}
	//-----------------------------------------------------------------------------------------------------------------------
	// Actions:
	//-----------------------------------------------------------------------------------------------------------------------
	// Informasi
	// Get Auth For First Time
	public function get_informasi_auth(String $otp_pin = '') {
		if (empty($otp_pin)) {
			return false;
		}
		if (!is_numeric($otp_pin)) {
			return false;
		}
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		$url_api = sprintf("%s/%s?msisdn=%s&pin=&s", 
			self::api_url, 
			'otp',
			$this->acc_num,
			$otp_pin
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_linkaja_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		return $http_data;
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	private function call_linkaja_gateway_server(String $method, String $url, Array $post_params = []) {
		$method = strtoupper($method);
		if (!in_array($method, ['GET', 'POST'])) {
			$method = 'GET';
		}
		
		curl_setopt($this->ch, CURLOPT_URL, $url);
		curl_setopt($this->ch, CURLOPT_REFERER, $url);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, $method);
		if ($method === 'POST') {
			curl_setopt($this->ch, CURLOPT_POST, TRUE);
			if (!empty($post_params)) {
				curl_setopt($this->ch, CURLOPT_POSTFIELDS, http_build_query($post_params));
			} else {
				curl_setopt($this->ch, CURLOPT_POSTFIELDS, '');
			}
		} else {
			curl_setopt($this->ch, CURLOPT_POST, FALSE);
			curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		}
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			
			return $http_body;
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}