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
		'ovo'			=> 'trf_ovo',
		'bank'			=> 'trf_other_bank',
		'cash_ovo'		=> 'OVO Cash',
		'cash_bank'		=> 'OVO Cash',
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

	//-----------------------------------------------------------------------------------------------------------------------
	// Actions:
	//-----------------------------------------------------------------------------------------------------------------------
	// Informasi
	
	
	
	
	
	
	
	
	
	
	
	
}