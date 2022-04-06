<?php
namespace Smbbk\Id\Gopay;

class Gopay {
    const API_URL 					= 'https://api.gojekapi.com';
    const API_GOID 					= 'https://goid.gojekapi.com';
    const API_CUSTOMER 				= 'https://customer.gopayapi.com';
    const clientId 					= 'gojek:consumer:app';
    const clientSecret 				= 'pGwQ7oi8bKqqwvid09UrjqpkMEHklb';
	const clientCountryCode			= '+62';
	const clientUseLink				= null;
    const appId 					= 'com.go-jek.ios';
    const phoneModel 				= 'Apple, iPhone XS Max';
    const phoneMake 				= 'Apple';
    const osDevice 					= 'iOS 14.8.1';
    const xPlatform 				= 'iOS';
    const appVersion 				= '4.34.0';
    const gojekCountryCode 			= 'ID';
    const userAgent 				= 'Gojek/4.34.0 (com.go-jek.ios; build:22264304; iOS 14.8.1) NetworkSDK/1.1.0';
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
	private $transfer_idempotency_key = '';
	public function __construct($acc_num, $cookie_path = '') {
		$this->acc_num = ((is_string($acc_num) || is_numeric($acc_num)) ? sprintf("%s", $acc_num) : '');
		if (strlen($this->acc_num) == 0) {
			return false;
		}
		$this->set_header_auth();
		$this->curl_options['user_agent'] = self::userAgent;
		$this->cookies_path = $cookie_path;
    }
	private function set_transfer_idempotency_key(String $trx_uuid) {
		$this->transfer_idempotency_key = $trx_uuid;
	}
	
	private function unique_trxid(String $transfer_id = '') {
		if (empty($transfer_id)) {
			$transfer_id = uniqid();
		}
		try {
			$microtime = microtime(true);
			$micro = sprintf("%06d",($microtime - floor($microtime)) * 1000000);
			$datetime = new \DateTime(date("Y-m-d H:i:s.{$micro}", $microtime));
			$datetime->setTimezone(new \DateTimeZone('Asia/Bangkok'));
			return sprintf("%s%s",
				$datetime->format('YmdHisu'),
				$transfer_id
			);
		} catch (Exception $ex) {
			throw $ex;
		}
	}
	
	
	
	private function set_uuidv4($input_params) {
		if (!isset($input_params['sessionId']) && !isset($input_params['uniqueId'])) {
			return;
		}
		$this->sessionId = $input_params['sessionId'];
        $this->uniqueId = $input_params['uniqueId'];
	}
	private function uuidv4() {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return strtoupper(vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data) , 4)));
    }
	public function generate_uuidv4() {
		return [
			'sessionId'				=> $this->uuidv4(),
			'uniqueId'				=> $this->uuidv4(),
		];
	}
	
	
	
	
	private function set_header_auth() {
		$this->headers = array(
			'Content-Type'				=> 'application/json',
			'Accept'					=> '*/*',
			'User-Agent'				=> self::userAgent,
			'Gojek-Country-Code'		=> self::gojekCountryCode,
			'x-appid'					=> self::appId,
			'x-phonemodel'				=> self::phoneModel,
			'x-phonemake'				=> self::phoneMake,
			'x-deviceos'				=> self::osDevice,
			'x-platform'				=> self::xPlatform,
			'x-appversion'				=> self::appVersion,
			'x-user-type'				=> self::$api_consumer,
		);
	}
	private function set_authorization($token = '') {
		$token = (is_string($token) ? sprintf("%s", $token) : '');
		if (strlen($token) == 0) {
			return false;
		}
		$this->authToken = $token;
		$this->headers['Authorization'] = sprintf("Bearer %s", $this->authToken);
		return $this->headers;
	}
	
	//-----------------------------------------------------------------------------------------------------------------------
	// Actions:
	//-----------------------------------------------------------------------------------------------------------------------
	// Get Auth For First Time
	public function get_informasi_auth() {
		$generated_uuid = $this->generate_uuidv4();
		$this->set_uuidv4($generated_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		$url_api = sprintf("%s/%s", self::API_GOID, 'goid/login/request');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		try {
			$http_data = $this->generate_informasi_auth();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (!isset($http_data->otp_token) || !isset($http_data->otp_length) || !isset($http_data->otp_expires_in)) {
			$http_response = [
				'status'			=> false,
				'data'				=> false,
				'error'				=> $http_data,
				'session'			=> $generated_uuid,
			];
		} else {
			$http_response = [
				'status'			=> true,
				'data'				=> $http_data,
				'error'				=> false,
				'session'			=> $generated_uuid,
			];
		}
		return $http_response;
	}
	private function generate_informasi_auth() {
		$post_params = array(
			'client_id'					=> self::clientId,
			'client_secret'				=> self::clientSecret,
			'country_code'				=> self::clientCountryCode,
			'magic_link_ref'			=> self::clientUseLink,
			'phone_number'				=> $this->acc_num,
		);
		$url_api = sprintf("%s/%s", self::API_GOID, 'goid/login/request');
		$url_referer = sprintf("%s/%s", self::API_GOID, 'goid/login/request');
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_api);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($this->ch, CURLOPT_POST, TRUE);
		curl_setopt($this->ch, CURLOPT_POSTFIELDS, json_encode($post_params, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
		
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			if (isset($http_body->success) && ($http_body->success === true)) {
				return $http_body->data;
			} else {
				return [
					'status'				=> false,
					'error'					=> (isset($http_body->errors) ? $http_body->errors : ''),
					'data'					=> null,
				];
			}
		}
	}
	public function get_informasi_token($otp_token, $otp_code, $session_params = array()) {
		$otp_token = (is_string($otp_token) ? sprintf("%s", $otp_token) : '');
		$otp_code = ((is_string($otp_code) || is_numeric($otp_code)) ? sprintf("%s", $otp_code) : '');
		
		if (empty($otp_code) || empty($otp_token)) {
			return false;
		}
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		$url_api = sprintf("%s/%s", self::API_GOID, 'goid/token');
		$url_referer = sprintf("%s/%s", self::API_GOID, 'goid/login/request');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		
		$post_params = array(
			'client_id'					=> self::clientId,
			'client_secret'				=> self::clientSecret,
			'data'						=> [
				'otp_token'						=> $otp_token,
				'otp'							=> $otp_code,
			],
			'grant_type'				=> 'otp',
		);
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($this->ch, CURLOPT_POST, TRUE);
		curl_setopt($this->ch, CURLOPT_POSTFIELDS, json_encode($post_params, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			if (!isset($http_body->access_token)) {
				return [
					'status'				=> false,
					'error'					=> (isset($http_body->errors) ? $http_body->errors : ''),
					'data'					=> null,
				];
			}
			return $http_body;
		}
		return false;
	}
	
	##########################
	# Set Authorization Heades
	##########################
	public function get_authorized_headers($token = '') {
		$token = (is_string($token) ? sprintf("%s", $token) : '');
		return $this->set_authorization($token);
	}
	// Get Informasi Rekening
	public function get_informasi_rekening($token = '', $session_params = array()) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_URL, 'gojek/v2/customer');
		$url_referer = sprintf("%s/%s", self::API_GOID, 'goid/token');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	// Get Informasi Saldo
	public function get_informasi_saldo($token = '', $session_params = array()) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$url_referer = sprintf("%s/%s", self::API_URL, 'gojek/v2/customer');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	// Get Informasi Mutasi
	public function get_informasi_mutasi($token = '', $session_params = array(), $page = 1, $limit = 100) {
		$page = (is_numeric($page) ? (int)$page : 1);
		$limit = (is_numeric($limit) ? (int)$limit : 400);
		
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		
		
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s?page=%d&limit=%d", 
			self::API_CUSTOMER, 
			'v1/users/transaction-history', 
			$page,
			$limit
		);
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	##
	# Transfer
	##
	// Get Bank List
	public function get_informasi_bank_lists(String $token = '', $session_params = array()) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_CUSTOMER, 'v1/banks?type=transfer&show_withdrawal_block_status=false');
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	// Get Informasi Phone Number
	public function get_informasi_phonenumber(String $phone_number, String $token = '', $session_params = array()) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s=%s", self::API_CUSTOMER, 'v1/users/p2p-profile?phone_number', $phone_number);
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	public function set_transfer_wallet(Array $input_params, String $token = '', $session_params = array()) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		if (!isset($input_params['transfer_params'])) {
			return false;
		}
		if (!isset($input_params['transfer_phonenumber'])) {
			return false;
		}
		if (!isset($input_params['transfer_pin'])) {
			return false;
		}
		$this->headers['pin'] = sprintf("%s", $input_params['transfer_pin']);
		
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_CUSTOMER, 'v1/funds/transfer');
		$url_referer = sprintf("%s/%s=%s", self::API_CUSTOMER, 'v1/users/p2p-profile?phone_number', $input_params['transfer_phonenumber']);
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		/*
		return [
			'url'						=> $url_api,
			'headers'					=> $headers,
			'post_params'				=> $input_params['transfer_params'],
		];
		*/
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($this->ch, CURLOPT_POST, TRUE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, FALSE);
		curl_setopt($this->ch, CURLOPT_POSTFIELDS, json_encode($input_params['transfer_params'], JSON_NUMERIC_CHECK));
		
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
	
	//----------------------------
	// Transfer Bank Purposes
	//----------------------------
	public function transfer_validate_bank(String $token = '', $session_params = array(), Array $input_params = []) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		
		try {
			$trx_uuid = $this->unique_trxid();
			$this->set_transfer_idempotency_key($trx_uuid);
		} catch (Exception $ex) {
			throw $ex;
		}
		
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		$this->headers['Idempotency-Key'] = $this->transfer_idempotency_key;
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s?bank_code=%s&account_number=%s", 
			self::API_CUSTOMER, 
			'v1/bank-accounts/validate',
			$input_params['bank_code'],
			$input_params['bank_number']
		);
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	public function transfer_get_bank_lists(String $token = '', $session_params = array()) {
		
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
		$this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		$this->headers['Idempotency-Key'] = $this->transfer_idempotency_key;
			
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_CUSTOMER, 'v1/banks?type=transfer&show_withdrawal_block_status=false');
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/payment-options/balances');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
		curl_setopt($this->ch, CURLOPT_POST, FALSE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		
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
	public function transfer_set_bank_transfer(String $token = '', $session_params = array(), Array $transfer_params = []) {
		$params_uuid = [
			'sessionId'				=> (isset($session_params['sessionId']) ? $session_params['sessionId'] : ''),
			'uniqueId'				=> (isset($session_params['uniqueId']) ? $session_params['uniqueId'] : ''),
		];
		if (empty($params_uuid['sessionId']) || empty($params_uuid['uniqueId'])) {
			return false;
		}
        $this->set_uuidv4($params_uuid);
		$this->headers['x-uniqueid'] = $this->uniqueId;
		$this->headers['x-session-id'] = $this->sessionId;
		$this->headers['Idempotency-Key'] = $this->transfer_idempotency_key;
        
		$transfer_params['transfer_params'] = array(
            'account_name' 				=> sprintf("%s", $transfer_params['transfer_name']),
            'account_number' 			=> sprintf("%s", $transfer_params['transfer_number']),
            'amount' 					=> sprintf("%s", $transfer_params['transfer_amount']),
            'bank_code' 				=> sprintf("%s", $transfer_params['transfer_bankcode']),
            'currency' 					=> 'IDR',
            'pin' 						=> sprintf("%s", $transfer_params['transfer_pin']),
            'type' 						=> 'transfer'
        );
		
		$headers = $this->get_authorized_headers($token);
		$url_api = sprintf("%s/%s", self::API_CUSTOMER, 'v1/withdrawals');
		$url_referer = sprintf("%s/%s", self::API_CUSTOMER, 'v1/banks?type=transfer&show_withdrawal_block_status=false');
		$this->set_curl_init($url_api, $this->create_curl_headers($headers));
		
		curl_setopt($this->ch, CURLOPT_URL, $url_api);
		curl_setopt($this->ch, CURLOPT_REFERER, $url_referer);
		curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
		curl_setopt($this->ch, CURLOPT_POST, TRUE);
		curl_setopt($this->ch, CURLOPT_HTTPGET, FALSE);
		curl_setopt($this->ch, CURLOPT_POSTFIELDS, json_encode($transfer_params['transfer_params']));
		
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
	
	
	
	
	
	//------------------------------------------
	
	
	
	
	
	function curlexec() {
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
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	//===========================================================================
	// Utils
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
	function set_headers($headers = array()) {
		$this->headers = $headers;
		return $this;
	}
	function reset_headers() {
		$this->headers = null;
		return $this;
	}
	
}




































