<?php
namespace Smbbk\Id\Brimo;

class Brimo {
	const api_url 					= 'https://brimo.btmsdigital.com';
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
		'timedout_execution'				=> 15,
		'timedout_connect'					=> 5,
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
	private static $cache_server_address = 'cache.bksmb.com';
	
	protected static $app_augipt = '';
	protected $acc_username = '';
	protected $acc_password = '';
	protected $acc_pin = '';
	
	
	public function __construct($acc_params, $cookie_path = '') {
		$this->acc_username = ((is_string($acc_params['acc_username']) || is_numeric($acc_params['acc_username'])) ? sprintf("%s", $acc_params['acc_username']) : '-');
		$this->acc_password = ((is_string($acc_params['acc_password']) || is_numeric($acc_params['acc_password'])) ? sprintf("%s", $acc_params['acc_password']) : '-');
		$this->acc_pin = ((is_string($acc_params['acc_pin']) || is_numeric($acc_params['acc_pin'])) ? sprintf("%s", $acc_params['acc_pin']) : '0');
		
		if ((strlen($this->acc_username) == 0) || (strlen($this->acc_password) == 0) || (strlen($this->acc_pin) == 0)) {
			return false;
		}
		$this->set_header_auth();
		$this->curl_options['user_agent'] = self::user_agent;
		$this->cookies_path = $cookie_path;
		
		$this->make_legacy_acc_num($this->acc_username);
    }
	private static function set_app_augipt(String $x_augipt) {
		self::$app_augipt = $x_augipt;
	}
	private function make_legacy_acc_num($acc_username = '') {
		$this->acc_num = $acc_username;
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
			'Content-Type'					=> 'application/x-www-form-urlencoded',
			'App-Id'						=> self::app_id,
			'App-Version'					=> self::app_version,
			'Os'							=> self::os_name,
			'Os-Version'					=> self::os_version,
			'User-Agent'					=> self::user_agent,
			'Authentication'				=> 'Bearer ' . self::app_authentication,
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
		self::set_app_augipt($this->authToken);
		
		
		$this->headers['X-Api-Authorization'] = sprintf("%s", $this->authToken);
		$this->headers['X-Augipt-Authorization'] = sprintf("%s", self::$app_augipt);
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
	public function get_acc_num() {
		return $this->acc_num;
	}
	public function get_acc_username() {
		return $this->acc_username;
	}
	//-----------------------------------------------------------------------------------------------------------------------
	// Actions:
	//-----------------------------------------------------------------------------------------------------------------------
	# If Logged In
	public function get_is_logged_in(String $token) {
		$this->set_authorization($token);
		$url_api = sprintf("%s/%s?json=1", 
			self::api_url, 
			'get_accounts'
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
			return $http_data;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	// Informasi
	// Get Auth For First Time
	public function get_informasi_auth(String $token, String $otp_pin = '') {
		$this->set_authorization($token);
		if (empty($otp_pin)) {
			return false;
		}
		if (!is_numeric($otp_pin)) {
			return false;
		}
		
		$url_api = sprintf("%s/%s?username=%s&password=%s&pin=%s", 
			self::api_url, 
			'add_account',
			$this->acc_username,
			$this->acc_password,
			$otp_pin
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		
		if (!isset($http_data->code) || !isset($http_data->description) || !isset($http_data->data->token_key)) {
			$http_response = [
				'status'			=> false,
				'data'				=> false,
				'error'				=> (isset($http_data->message) ? $http_data->message : $http_data),
			];
		} else {
			$http_response = [
				'status'			=> true,
				'data'				=> $http_data,
				'error'				=> false,
			];
		}
		
		return $http_response;
	}
	// Verify OTP Code
	public function verify_otp_code(String $token, String $otp_pin, String $otp_code = '') {
		$this->set_authorization($token);
		if (empty($otp_pin) || empty($otp_code)) {
			return false;
		}
		if (!is_numeric($otp_pin)) {
			return false;
		}
		$otp_params = [
			'pin'		=> strval($otp_pin),
			'code'		=> strval($otp_code)
		];
		
		$url_api = sprintf("%s/%s?username=%s&sms=%s", 
			self::api_url, 
			'add_account_verify',
			$this->acc_username,
			$otp_code
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		
		if (!isset($http_data->code) || !isset($http_data->data->username)) {
			$http_response = [
				'status'			=> false,
				'data'				=> false,
				'error'				=> (isset($http_data->message) ? $http_data->message : $http_data),
			];
		} else {
			$http_response = [
				'status'			=> true,
				'data'				=> $http_data,
				'error'				=> false,
			];
		}
		return $http_response;
	}
	
	// Get Auth For Relogin
	public function get_informasi_relogin(String $token, String $otp_pin = '') {
		$this->set_authorization($token);
		if (empty($otp_pin)) {
			return false;
		}
		if (!is_numeric($otp_pin)) {
			return false;
		}
		$url_api = sprintf("%s/%s?username=%s", 
			self::api_url, 
			'relogin',
			$this->acc_username
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		
		if (!isset($http_data->code) || !isset($http_data->description) || !isset($http_data->data->token_key)) {
			$http_response = [
				'status'			=> false,
				'data'				=> false,
				'error'				=> (isset($http_data->message) ? $http_data->message : $http_data),
			];
		} else {
			$http_response = [
				'status'			=> true,
				'data'				=> $http_data,
				'error'				=> false,
			];
		}
		
		return $http_response;
	}
	//-----------------------------------------------------------------------------------------------------------------------
	public function get_account_data(String $token, Array $session_params = array()) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		
		$url_api = sprintf("%s/%s?username=%s", 
			self::api_url, 
			'balance',
			$this->acc_username
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		if (!isset($http_data->data)) {
			$http_response = [
				'status'			=> false,
				'data'				=> false,
				'error'				=> (isset($http_data->message) ? $http_data->message : $http_data),
			];
		} else {
			$http_response = [
				'status'			=> true,
				'data'				=> $http_data,
				'error'				=> false,
			];
		}
		return $http_response;
	}
	// Get Informasi Saldo
	public function get_informasi_saldo($token = '', $session_params = array()) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		
		$url_api = sprintf("%s/%s?username=%s", 
			self::api_url, 
			'balance',
			$this->acc_username
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		return $http_data;
	}
	// Get Informasi Mutasi
	public function get_informasi_mutasi(String $token, Array $session_params, Array $date_params = ['start_date' => '2022-01-01', 'end_date' => '2022-01-01']) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		if (!isset($date_params['start_date']) || !isset($date_params['end_date'])) {
			return false;
		}
		$url_api = sprintf("%s/%s?username=%s&start_date=%s&end_date=%s&json=1", 
			self::api_url, 
			'mutasi',
			$this->acc_username,
			$date_params['start_date'],
			$date_params['end_date']
		);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
		} catch (Exception $ex) {
			throw $ex;
		}
		return $http_data;
	}
	
	# Logout
	public function set_informasi_logout(String $token, String $acc_username) {
		$this->set_authorization($token);
		if (strtolower($acc_username) !== strtolower($this->acc_username)) {
			return false;
		}
		
		// Logout
		$url_api_logout = sprintf("%s/%s?username=%s", 
			self::api_url, 
			'logout',
			$this->acc_username
		);
		$this->set_curl_init($url_api_logout, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api_logout, []);
			return $http_data;
		} catch (Exception $ex) {
			throw $ex;
		}
		
		return $http_datas;
	}
	# Delete
	public function set_informasi_delete_account(String $token, String $acc_username) {
		$this->set_authorization($token);
		if (strtolower($acc_username) !== strtolower($this->acc_username)) {
			return false;
		}
		
		// Delete
		$url_api_delete = sprintf("%s/%s?username=%s", 
			self::api_url, 
			'delete_account',
			$this->acc_username
		);
		$this->set_curl_init($url_api_delete, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api_delete, []);
			return $http_data;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	
	
	
	
	// TRANSFER
	public function get_transfer_bank_lists(String $token, String $acc_username) {
		$this->set_authorization($token);
		if (strtolower($acc_username) !== strtolower($this->acc_username)) {
			return false;
		}
		$url_api = sprintf("%s/%s?username=%s&json=1", 
			self::api_url, 
			'listBank',
			$this->acc_username
		);
		
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
			return $http_data;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	public function transfer_set_wallet(Array $input_params, String $transfer_step = 'validate') {
		$transfer_instance = 'wallet';
		$transfer_step = (isset($transfer_step) ? strtolower($transfer_step) : 'validate');
		if (!in_array($transfer_step, ['validate', 'process', 'unlock'])) {
			$transfer_step = 'validate';
		}
		// Check Input Params
		if (!isset($input_params['transfer_instance'])) {
			return false;
		} else {
			$transfer_instance = (is_string($input_params['transfer_instance']) ? strtolower(trim($input_params['transfer_instance'])) : '');
			if (!in_array($transfer_instance, ['wallet', 'bank'])) {
				return false;
			}
		}
		if (!isset($input_params['transfer_amount']) || !isset($input_params['transfer_number'])) {
			return false;
		} else {
			$input_params['transfer_amount'] = (is_numeric($input_params['transfer_amount']) ? sprintf("%d", $input_params['transfer_amount']) : 0);
			if ($input_params['transfer_amount'] == 0) {
				return;
			}
			if ($input_params['transfer_amount'] < self::$transfer_minimum[$transfer_instance]) {
				return sprintf("Transfer minimum is %s IDR", number_format(self::$transfer_minimum[$transfer_instance], 2));
			}
			$input_params['transfer_number'] = (is_numeric($input_params['transfer_number']) ? sprintf("%s", $input_params['transfer_number']) : '');
			if (!preg_match('/(^0([8|9])+([0-9]+))$/', $input_params['transfer_number'])) {
				return false;
			}
		}
		
		switch ($transfer_step) {
			case 'process':
				if (!isset($input_params['transfer_id']) || !isset($input_params['transfer_pin'])) {
					return ("Required transfer_id and transfer_pin");
				} else {
					$collected_params = array();
					$input_params['transfer_pin'] = ((is_string($input_params['transfer_pin']) || is_numeric($input_params['transfer_pin'])) ? sprintf("%s", trim($input_params['transfer_pin'])) : '');
					$input_params['transfer_id'] = (is_string($input_params['transfer_id']) ? sprintf("%s", trim($input_params['transfer_id'])) : '');
					
					$input_params['transfer_amount'] = sprintf("%d", $input_params['transfer_amount']);
					$collected_params['post_params'] = [
						'amount'		=> sprintf('%d', $input_params['transfer_amount']),
						'trxId'			=> sprintf("%s", $input_params['transfer_id']),
						'to'			=> sprintf("%s", $input_params['transfer_number']),
						'message'		=> ((isset($input_params['transfer_message']) && is_string($input_params['transfer_message'])) ? substr(sprintf("%s", $input_params['transfer_message']), 0, 32) : sprintf("%s from %s", uniqid(), $this->acc_num)),
					];
					
					$collected_params['url_api_transfer'] = sprintf("%s/%s?msisdn=%s&pin=%s&to=%s&amount=%d&trxid=%s&berita=%s", 
						self::api_url, 
						'transfer',
						$this->acc_num,
						$input_params['transfer_pin'],
						$collected_params['post_params']['to'],
						$collected_params['post_params']['amount'],
						$collected_params['post_params']['trxId'],
						$collected_params['post_params']['message']
					);
					$this->set_curl_init($collected_params['url_api_transfer'], $this->create_curl_headers($this->headers));
					try {
						$collected_params['http_data'] = $this->call_brimo_gateway_server('GET', $collected_params['url_api_transfer'], []);
					} catch (Exception $ex) {
						throw $ex;
					}
					return $collected_params;
				}
			break;
			case 'validate':
			default:
				try {
					$transaction_data = $this->transfer_generate_transaction_id($input_params);
				} catch (Exception $ex) {
					throw $ex;
				}
				return $transaction_data;
			break;
		}
	}
	

	private function call_brimo_gateway_server(String $method, String $url, Array $post_params = []) {
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
	# Transfer get-data
	public function get_transfer_cache_data_by_trxid(String $token, String $transfer_id, Int $expired_seconds) {
		$this->set_authorization($token);
		if (!is_numeric($expired_seconds)) {
			return false;
		}
		$post_params = [
			'trxid'			=> $transfer_id,
			'expired'		=> $expired_seconds,
		];
		$apiurl_endpoint = sprintf("https://%s/transfer/generate/trxid/%s", 
			self::$cache_server_address,
			$post_params['trxid']
		);
		try {
			$transfer_cache = $this->send_transfer_transaction_cache($apiurl_endpoint, $post_params);
			$transfer_cache = json_decode($transfer_cache);
			return $transfer_cache;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	# Transfer Make
	public function transfer_set_bank(String $token, Array $input_params) {
		$status = FALSE;
		$this->set_authorization($token);
		if (!isset($input_params['transfer_id'])) {
			return false;
		}
		try {
			$clean_cache = $this->transfer_clean_trxid_from_cache($this->authToken, $input_params);
		} catch (Exception $ex) {
			throw $ex;
		}
		if (!isset($clean_cache->status)) {
			return false;
		}
		if ($clean_cache->status === TRUE) {
			$url_api = sprintf("%s/%s?username=%s&pin=%s&code=%03s&to=%s&amount=%s&idtrx=%s&json=1", 
				self::api_url, 
				'transfer',
				$this->acc_username,
				$input_params['transfer_pin'],
				$input_params['transfer_bankcode'],
				$input_params['transfer_number'],
				$input_params['transfer_amount'],
				$input_params['transfer_id']
			);
			try {
				$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
				$http_data = $this->call_brimo_gateway_server('GET', $url_api, []);
				if ($http_data != FALSE) {
					$status = TRUE;
				}
			} catch (Exception $ex) {
				throw $ex;
			}
		} else {
			$http_data = FALSE;
		}
		return [
			'status'		=> $status,
			'data'			=> $http_data
		];
	}
	private function transfer_clean_trxid_from_cache(String $token, Array $input_params) {
		if (!isset($input_params['transfer_id'])) {
			return false;
		}
		$post_params = [
			'trxid'			=> $input_params['transfer_id'],
			'expired'		=> 0,
		];
		$apiurl_endpoint = sprintf("https://%s/transfer/generate/cleanuuid/%s", 
			self::$cache_server_address,
			$post_params['trxid']
		);
		try {
			$clean_cache = $this->send_transfer_transaction_cache($apiurl_endpoint, $post_params);
			$clean_cache = json_decode($clean_cache);
			return $clean_cache;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	# Transfer validate transaction-id
	public function transfer_generate_transaction_id(String $token, Array $input_params) {
		$this->set_authorization($token);
		if (!isset($input_params['transfer_id'])) {
			return false;
		}
		$post_params = [
			'trxid'			=> $this->unique_trxid($input_params['transfer_id']),
			'expired'		=> 600,
			'data'			=> array(
				'acc_num'			=> $this->acc_username,
				'acc_username'		=> $this->acc_username,
				'amount'			=> (isset($input_params['transfer_amount']) ? $input_params['transfer_amount'] : 0),
			)
		];
		if (isset($input_params['transfer_created'])) {
			$post_params['data']['transfer_created'] = $input_params['transfer_created'];
		}
		if (isset($input_params['transfer_number'])) {
			$post_params['data']['transfer_number'] = $input_params['transfer_number'];
		}
		try {
			$apiurl_endpoint = sprintf("https://%s/transfer/generate/create/%s", 
				self::$cache_server_address,
				$post_params['trxid']
			);
			$transaction_cache = $this->send_transfer_transaction_cache($apiurl_endpoint, $post_params);
			$transaction_cache = json_decode($transaction_cache);
			return $transaction_cache;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	private function unique_trxid(String $transfer_id = '') {
		try {
			$microtime = microtime(true);
			$micro = sprintf("%06d",($microtime - floor($microtime)) * 1000000);
			$datetime = new \DateTime(date("Y-m-d H:i:s.{$micro}", $microtime));
			$datetime->setTimezone(new \DateTimeZone('Asia/Bangkok'));
			return sprintf("%s%s",
				$transfer_id,
				$datetime->format('YmdHisu')
			);
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	public function transfer_initialized_transaction_id(String $token, String $transaction_id, String $process_step = 'validate') {
		$this->set_authorization($token);
		
		if (!isset($transaction_id)) {
			return false;
		}
		if (!in_array($process_step, ['validate', 'process'])) {
			$process_step = 'validate';
		}
		$post_params = [
			'trxid'			=> $transaction_id,
			'expired'		=> 30,
		];
		if ($process_step === 'process') {
			$apiurl_endpoint = sprintf("https://%s/transfer/generate/trxid/%s", 
				self::$cache_server_address,
				$transaction_id
			);
		} else {
			$apiurl_endpoint = sprintf("https://%s/transfer/generate/trxid/%s", 
				self::$cache_server_address,
				$transaction_id
			);
			$post_params['expired'] = 600;
		}
		return $this->send_transfer_transaction_cache($apiurl_endpoint, $post_params);
	}
	private function send_transfer_transaction_cache(String $url, Array $post_params) {
		$curl_setopts = [
			CURLOPT_URL					=> $url,
			CURLOPT_HTTPHEADER			=> FALSE,
			CURLOPT_RETURNTRANSFER 		=> true,
			CURLOPT_ENCODING 			=> "",
			CURLOPT_MAXREDIRS 			=> 4,
			CURLOPT_TIMEOUT 			=> 0,
			CURLOPT_FOLLOWLOCATION 		=> true,
			CURLOPT_HTTP_VERSION 		=> CURL_HTTP_VERSION_1_1,
			CURLOPT_HTTPHEADER			=> [
				'Content-type: application/json',
				'Accept: application/json',
				'X-Caller-Service: BK Augipt Cache Service'
			],
			CURLOPT_CUSTOMREQUEST		=> 'POST',
			CURLOPT_POST				=> TRUE,
			CURLOPT_HTTPGET				=> FALSE
		];
		$curl_setopts[CURLOPT_POSTFIELDS] = json_encode($post_params);
		
		$curl_setopts[CURLOPT_SSL_VERIFYHOST] = 2;
		$curl_setopts[CURLOPT_SSL_VERIFYPEER] = FALSE;
		
		
		try {
			$curl = curl_init();
			curl_setopt_array($curl, $curl_setopts);
			$response = curl_exec($curl);
			curl_close($curl);
			
			return $response;
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	
	

}