<?php
namespace Smbbk\Id\Ovo;

class Ovo {
	const api_url 					= 'https://api.ovo.id';
    const heusc_api 				= 'https://agw.heusc.id';
	const api_agw					= 'https://agw.ovo.id';
	//const heusc_api 				= 'https://apigw01.aws.ovo.id';
    const os_name 					= 'iOS';
    const os_version 				= '14.4.2';
    const app_id 					= 'P72RVSPSF61F72ELYLZI';
    const app_version 				= '3.49.0';
    const user_agent 				= 'OVO/17767 CFNetwork/1220.1 Darwin/20.3.0';
    const action_mark 				= 'OVO Cash';
	const client_id					= "ovo_ios";
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
		'wallet'		=> 'trf_ovo',
		'ovo'			=> 'trf_ovo',
		'bank'			=> 'trf_other_bank',
		'cash_ovo'		=> 'OVO Cash',
		'cash_bank'		=> 'OVO Cash',
	];
	private static $transfer_minimum = [
		'ovo'			=> 10000,
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
			'Content-Type'			=> 'application/json',
			'App-Id'				=> self::app_id,
			'App-Version'			=> self::app_version,
			'Os'					=> self::os_name,
			'Os-Version'			=> self::os_version,
			'User-Agent'			=> self::user_agent,
			'Accept'				=> '*/*',
			'Accept-Encoding'		=> 'deflate, gzip',
        );
        return $this->headers;
	}
	public function set_device_id(String $device_id) {
		$this->device_id = $device_id;
	}
	public function set_push_notif_id(String $push_notif_id) {
		$this->push_notif_id = $push_notif_id;
	}
	
	public function get_ovoid_headers() {
		return $this->headers;
	}
	public function generate_authorized_headers($token = '', $device_id = null) {
		$token = (is_string($token) ? sprintf("%s", $token) : '');
		if (strlen($token) == 0) {
			return false;
		}
		if (!isset($device_id)) {
			$device_id = $this->device_id;
		}
		$this->authToken = $token;
		$this->headers['Authorization'] = sprintf("%s", $this->authToken);
		$this->headers['Os-Version'] = sprintf("%s", self::os_version);
		$this->headers['Client-Id'] = sprintf("%s", self::client_id);
		$this->headers['Device-Id'] = sprintf("%s", $device_id);
		return $this->headers;
	}
	##
	# Get Account Number
	##
	public function get_acc_num() {
		return $this->acc_num;
	}
	
	
	
	private function set_authorization($token = '', $device_id = null) {
		$token = (is_string($token) ? sprintf("%s", $token) : '');
		if (strlen($token) == 0) {
			return false;
		}
		if (!isset($device_id)) {
			$device_id = $this->device_id;
		}
		$this->authToken = $token;
		$this->headers['Authorization'] = sprintf("%s", $this->authToken);
		$this->headers['Os-Version'] = sprintf("%s", self::os_version);
		$this->headers['Client-Id'] = sprintf("%s", self::client_id);
		$this->headers['Device-Id'] = sprintf("%s", $device_id);
		return $this->headers;
	}

	//-----------------------------------------------------------------------------------------------------------------------
	// Actions:
	//-----------------------------------------------------------------------------------------------------------------------
	// Informasi
	public function login2FA() {
		$post_params = array(
            'msisdn'			=> $this->acc_num,
            'device_id' 		=> $this->device_id,
        );
		
		$url_api = sprintf("%s/%s", self::heusc_api, 'v3/user/accounts/otp');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	public function loginVerify(String $reference_id, String $otp_code) {
		$post_params = array(
            'msisdn'			=> $this->acc_num,
            'device_id' 		=> $this->device_id,
			'reff_id'			=> $reference_id,
			'otp_code'			=> $otp_code,
        );
		
		$url_api = sprintf("%s/%s", self::heusc_api, 'v3/user/accounts/otp/validation');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	public function loginToken(String $otp_token, String $pin) {
		if (empty($otp_token)) {
			return false;
		} else {
			$otp_token = sprintf("%s", $otp_token);
		}
		$pin = (is_numeric($pin) ? sprintf("%s", $pin) : '');
		if (empty($pin)) {
			return false;
		}
		$post_params = array(
            'msisdn'			=> $this->acc_num,
			'device_id'			=> $this->device_id,
			'otp_token'			=> $otp_token,
            'security_code' 	=> $pin,
        );
		$url_api = sprintf("%s/%s", self::heusc_api, 'v3/user/accounts/login');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
    }
	//-----------------------------------------------------------------------------------------------------------------------
	public function get_account_data(String $token, Array $session_params = array()) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		$url_api = sprintf("%s/%s", self::api_url, 'wallet/inquiry');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body(FALSE);
		
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	public function get_ovo_profile_email(String $token, Array $session_params, String $mobilephone = '') {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		$url_api = sprintf("%s/%s", self::api_agw, 'v3/user/accounts/email');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body(FALSE);
		
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	public function get_ovo_profile_data(String $token, Array $session_params, String $mobilephone = '') {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		$post_params = array(
            'mobile'			=> $mobilephone
        );
        
		$url_api = sprintf("%s/%s", self::api_url, 'v1.1/api/auth/customer/isOVO');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
    }
	
	
	
	// Get Transaction History
	public function get_ovo_transaction_history(String $token, Array $session_params, Array $pagination_params = ['page' => 1, 'limit' => 100]) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		$pagination_params = [
			'page'					=> (is_numeric($pagination_params['page']) ? (int)$pagination_params['page'] : 1),
			'limit'					=> (is_numeric($pagination_params['limit']) ? (int)$pagination_params['limit'] : 100),
		];
		
		$url_api = sprintf("%s/%s?page=%d&limit=%d", self::api_url, 'wallet/v2/transaction', $pagination_params['page'], $pagination_params['limit']);
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body(FALSE);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	
	##
	# Transfer Balance
	##
	private function make_transaction_id_wallet(Array $input_params) {
		$post_params = [
			'actionMark'			=> (isset($input_params['actionMark']) ? sprintf("%s", $input_params['actionMark']) : self::$transfer_action_mark['ovo']),
			'amount'				=> (isset($input_params['amount']) ? sprintf("%d", $input_params['amount']) : 0),
		];
		
		
		$url_api = sprintf("%s/%s", self::api_url, 'v1.0/api/auth/customer/genTrxId');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
		
	}
	public function generateTrxId($amount, $action_mark = "OVO Cash") {
        $field = array(
            'amount' => $amount,
            'actionMark' => $action_mark
        );
        
        return self::request(self::api_url . '/v1.0/api/auth/customer/genTrxId', $field, $this->headers());
    }
	protected function generateSignature($amount, $trx_id) {
        return sha1(join('||', array(
            $trx_id,
            $amount,
            $this->device_id
        )));
    }
    public function unlockAndValidateTrxId($amount, $trx_id, $security_code) {
        $field = array(
            'trxId' => $trx_id,
            'securityCode' => $security_code,
            'signature' => $this->generateSignature($amount, $trx_id)
        );
        
        return self::request(self::api_url . '/v1.0/api/auth/customer/unlockAndValidateTrxId', $field, $this->headers());
    }
	
	
	
	
	private function transfer_generate_transaction_id(Array $input_params, String $instance_type = 'wallet') {
		$transfer_instance = 'ovo';
		// Check Input Params
		if (!isset($input_params['transfer_instance'])) {
			return false;
		} else {
			$transfer_instance = (is_string($input_params['transfer_instance']) ? strtolower(trim($input_params['transfer_instance'])) : '');
			if (!in_array($transfer_instance, ['wallet', 'ovo', 'bank'])) {
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
				return new ResponseException(sprintf("Transfer minimum is %s IDR", number_format(self::$transfer_minimum[$transfer_instance], 2)));
			}
			$input_params['transfer_number'] = (is_numeric($input_params['transfer_number']) ? sprintf("%s", $input_params['transfer_number']) : '');
		}
		$session_params = [
			'device_id'			=> $this->device_id,
			'push_notif_id'		=> $this->push_notif_id,
		];
		switch ($transfer_instance) {
			case 'bank':
				try {
					$receiver_data = $this->get_bank_profile_data($this->authToken, $session_params, $input_params);
				} catch (Exception $ex) {
					throw new ResponseException("Cannot get account profile data on tranfer-bank with exception: {$ex->getMessage()}.");
				}
			break;
			case 'wallet':
			case 'ovo':
			default:
				if (!preg_match('/(^0([8|9])+([0-9]+))$/', $input_params['transfer_number'])) {
					return new ResponseException("Invalid phone number.");
				} else {
					try {
						$receiver_data = $this->get_ovo_profile_data($this->authToken, $session_params, $input_params['transfer_number']);
					} catch (Exception $ex) {
						throw new ResponseException("Cannot get account profile data on tranfer-wallet with exception: {$ex->getMessage()}.");
					}
				}
			break;
		}
		
		switch ($transfer_instance) {
			case 'bank':
				if (!isset($receiver_data->accountNo) || !isset($receiver_data->bankCode)) {
					return false;
				} else {
					if (sprintf("%s", trim($receiver_data->accountNo)) === sprintf("%s", $input_params['transfer_number'])) {
						try {
							$post_params = array(
								'actionMark'			=> self::$transfer_action_mark[$instance_type],
								'amount'				=> sprintf("%d", $input_params['transfer_amount']),
							);
							$generated_transfer_id = $this->make_transaction_id_bank($post_params);
							if (!isset($generated_transfer_id->trxId)) {
								return new ResponseException("Unpexted response from api-server.");
							}
						} catch (Exception $ex) {
							throw $ex->getMessage();
						}
					} else {
						return false;
					}
				}
			break;
			case 'wallet':
			case 'ovo':
			default:
				if (!isset($receiver_data->mobile)) {
					return false;
				} else {
					if (sprintf("%s", trim($receiver_data->mobile)) === sprintf("%s", $input_params['transfer_number'])) {
						try {
							$post_params = array(
								'actionMark'			=> self::$transfer_action_mark[$transfer_instance],
								'amount'				=> sprintf("%d", $input_params['transfer_amount']),
							);
							
							$generated_transfer_id = $this->make_transaction_id_wallet($post_params);
							if (!isset($generated_transfer_id->trxId)) {
								return new ResponseException("Unpexted response from api-server.");
							}
						} catch (Exception $ex) {
							throw $ex->getMessage();
						}
					} else {
						return false;
					}
				}
			break;
		}
		return [
			'transfer_transaction_id'	=> $generated_transfer_id->trxId,
			'payment_id'				=> $generated_transfer_id->trxId,
			'receiver_data'				=> $receiver_data,
		];		
	}
	
	
	
	private function transfer_set_wallet_unlock(Array $collected_params, Array $input_params) {
		$collected_params['unlok_response'] = $this->unlock_transaction_id($input_params['transfer_id'], $input_params);
		if (!isset($collected_params['unlok_response']['http_body']->isAuthorized)) {
			throw new ResponseException("Not have authorized unlocked transaction from api-server.");
		} else {
			if (isset($collected_params['unlok_response']['post_params']['signature'])) {
				//$this->headers['x-signature'] = sprintf("%s", $collected_params['unlok_response']['post_params']['signature']);
				$collected_params['post_params']['signature'] = sprintf("%s", $collected_params['unlok_response']['post_params']['signature']);
			}
			if (isset($collected_params['unlok_response']['post_params']['securityCode'])) {
				//$collected_params['post_params']['securityCode'] = sprintf("%d", $collected_params['unlok_response']['post_params']['securityCode']);
			}
			$collected_params['post_params']['amount'] = intval($collected_params['post_params']['amount']);
			// Sleep 5 second(s) wait for OVO rest on queue
			sleep(5);
			if (is_string($collected_params['unlok_response']['http_body']->isAuthorized) && (strtolower($collected_params['unlok_response']['http_body']->isAuthorized) === 'true')) {
				$collected_params['transfer_post_params'] = $collected_params['post_params'];
				$collected_params['transfer_headers'] = $this->headers;
				$collected_params['transfer_url'] = $collected_params['url_api_transfer'];
				
				$this->set_curl_init($collected_params['url_api_transfer'], $this->create_curl_headers($this->headers));
				$this->set_curl_body($collected_params['post_params']);
				try {
					$collected_params['transfer_response'] = $this->curlexec();
					$collected_params['transfer_data'] = json_decode($collected_params['transfer_response']['http_body']);
				} catch (Exception $ex) {
					throw $ex;
				}
			}
		}
		return $collected_params;
	}
	public function transfer_set_wallet(Array $input_params, String $transfer_step = 'validate') {
		$transfer_instance = 'ovo';
		$transfer_step = (isset($transfer_step) ? strtolower($transfer_step) : 'validate');
		if (!in_array($transfer_step, ['validate', 'process', 'unlock'])) {
			$transfer_step = 'validate';
		}
		// Check Input Params
		if (!isset($input_params['transfer_instance'])) {
			return false;
		} else {
			$transfer_instance = (is_string($input_params['transfer_instance']) ? strtolower(trim($input_params['transfer_instance'])) : '');
			if (!in_array($transfer_instance, ['wallet', 'ovo', 'bank'])) {
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
				return new ResponseException(sprintf("Transfer minimum is %s IDR", number_format(self::$transfer_minimum[$transfer_instance], 2)));
			}
			$input_params['transfer_number'] = (is_numeric($input_params['transfer_number']) ? sprintf("%s", $input_params['transfer_number']) : '');
			if (!preg_match('/(^0([8|9])+([0-9]+))$/', $input_params['transfer_number'])) {
				return false;
			}
		}
		
		switch ($transfer_step) {
			case 'unlock':
				if (!isset($input_params['transfer_id']) || !isset($input_params['transfer_pin'])) {
					return new ResponseException("Required transfer_id and transfer_pin");
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
					//$collected_params['post_params']['message'] = '';
					return $this->transfer_set_wallet_unlock($collected_params, $input_params);
				}
			break;
			case 'process':
				if (!isset($input_params['transfer_id']) || !isset($input_params['transfer_pin'])) {
					return new ResponseException("Required transfer_id and transfer_pin");
				} else {
					$collected_params = array(
						'url_api_transfer'			=> sprintf("%s/%s", self::api_url, 'v1.0/api/customers/transfer/'),
					);
					$input_params['transfer_pin'] = ((is_string($input_params['transfer_pin']) || is_numeric($input_params['transfer_pin'])) ? sprintf("%s", trim($input_params['transfer_pin'])) : '');
					$input_params['transfer_id'] = (is_string($input_params['transfer_id']) ? sprintf("%s", trim($input_params['transfer_id'])) : '');
					
					$input_params['transfer_amount'] = sprintf("%d", $input_params['transfer_amount']);
					$collected_params['post_params'] = [
						'amount'		=> sprintf('%d', $input_params['transfer_amount']),
						'trxId'			=> sprintf("%s", $input_params['transfer_id']),
						'to'			=> sprintf("%s", $input_params['transfer_number']),
						'message'		=> ((isset($input_params['transfer_message']) && is_string($input_params['transfer_message'])) ? substr(sprintf("%s", $input_params['transfer_message']), 0, 32) : sprintf("%s from %s", uniqid(), $this->acc_num)),
					];
					//$collected_params['post_params']['message'] = '';
					/*
					preg_match('/(^0([8|9])+([0-9]+))$/', $input_params['transfer_number'], $transfer_number_matchs);
					if (isset($transfer_number_matchs[2]) && isset($transfer_number_matchs[3])) {
						$collected_params['post_params']['to'] = sprintf("+62%s%s", $transfer_number_matchs[2], $transfer_number_matchs[3]);
					}
					*/
					$collected_params['post_fields'] = json_encode($collected_params['post_params']);
					
					//$collected_params['unlock_transfers'] = $this->transfer_set_wallet_unlock($collected_params, $input_params);
					
					# Try Unlock
					/*
					$collected_params['try_unlok_response'] = $this->unlock_transaction_id($input_params['transfer_id'], $input_params);
					if (!isset($collected_params['try_unlok_response']['http_body']->isAuthorized)) {
						throw new ResponseException("Not have authorized try-unlocked transaction from api-server on wallet-transfer.");
					} else {
						if (isset($collected_params['try_unlok_response']['post_params']['signature'])) {
							
						}
						if (is_string($collected_params['try_unlok_response']['http_body']->isAuthorized) && (strtolower($collected_params['try_unlok_response']['http_body']->isAuthorized) === 'true')) {
							$url_api = sprintf("%s/%s", self::api_url, 'v1.0/api/customers/transfer/');
							$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
							$this->set_curl_body($collected_params['post_params']);
							try {
								$collected_params['unlock_and_transfers'] = $this->curlexec();
								if (isset($collected_params['unlock_and_transfers']['http_code']) && ($collected_params['unlock_and_transfers']['http_code'] == 500)) {
									$this->set_curl_init(sprintf("%s/%s", self::api_url, 'v1.0/api/customers/transfer/'), $this->create_curl_headers($this->headers));
									$this->set_curl_body($collected_params['post_params']);
									$collected_params['again_transfers'] = $this->curlexec();
								}
							} catch (Exception $ex) {
								throw $ex;
							}
							print_r($collected_params);
							exit;
						}
					}
					*/
					$this->set_curl_init($collected_params['url_api_transfer'], $this->create_curl_headers($this->headers));
					$this->set_curl_body($collected_params['post_params']);
					try {
						$collected_params['curl_collect'] = $this->curlexec();
					} catch (Exception $ex) {
						throw $ex;
					}
					if (isset($collected_params['curl_collect']['http_body'])) {
						try {
							$collected_params['try_transfer'] = json_decode($collected_params['curl_collect']['http_body']);
						
							if (isset($collected_params['try_transfer']->message) && is_string($collected_params['try_transfer']->message)) {
								$collected_params['try_transfer_message'] = trim(strtolower($collected_params['try_transfer']->message));
								if ($collected_params['try_transfer_message'] == 'sorry unable to handle your request') {
									$collected_params['unlock_transfers'] = $this->transfer_set_wallet_unlock($collected_params, $input_params);
								}
							}
						} catch (Exception $ex) {
							throw $ex;
						}
					}
					return $collected_params;
				}
			break;
			case 'validate':
			default:
				$wallet_transfer_actionmark = 'wallet';
				if (isset($input_params['transfer_action_mark']) && is_string($input_params['transfer_action_mark'])) {
					$input_params['transfer_action_mark'] = strtolower($input_params['transfer_action_mark']);
					$wallet_transfer_actionmark = $input_params['transfer_action_mark'];
				}
				try {
					// $transaction_data = $this->transfer_generate_transaction_id($input_params, 'wallet');
					$transaction_data = $this->transfer_generate_transaction_id($input_params, $wallet_transfer_actionmark);
				} catch (Exception $ex) {
					throw new ResponseException("Cannot generate transaction-id with exception: {$ex->getMessage()}.");
				}
				return $transaction_data;
			break;
		}
	}
	
	private function unlock_transaction_id(String $transaction_id, Array $input_params) {
		$input_params['transfer_pin'] = (isset($input_params['transfer_pin']) ? $input_params['transfer_pin'] : '');
		
		
		$input_params['transfer_signature'] = $this->generate_unlock_signature($transaction_id, $input_params['transfer_amount']);
		$post_params = [
			'trxId'				=> $transaction_id,
			'signature'			=> $input_params['transfer_signature'],
			'appVersion'		=> self::app_version,
			'securityCode'		=> $input_params['transfer_pin'],
		];
		
		$url_api = sprintf("%s/%s", self::api_url, 'v1.0/api/auth/customer/unlockAndValidateTrxId');
		//$this->headers['x-signature'] = $input_params['transfer_signature'];
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return [
				'http_body'			=> $http_body,
				'post_params'		=> $post_params,
			];
		}
		return false;
    }
	private function generate_unlock_signature(String $transaction_id, $transfer_amount) {
		$string = sprintf("%s||%d||%s",
			$transaction_id,
			$transfer_amount,
			$this->device_id
		);
        return sha1($string);
	}
	# Bank Transfer
	public function transfer_set_bank(Array $input_params, String $transfer_step = 'validate') {
		$transfer_instance = 'bank';
		$transfer_step = (isset($transfer_step) ? strtolower($transfer_step) : 'validate');
		if (!in_array($transfer_step, ['validate', 'process'])) {
			$transfer_step = 'validate';
		}
		// Check Input Params
		if (!isset($input_params['transfer_instance'])) {
			return false;
		} else {
			$transfer_instance = (is_string($input_params['transfer_instance']) ? strtolower(trim($input_params['transfer_instance'])) : 'bank');
			if (!in_array($transfer_instance, ['wallet', 'ovo', 'bank'])) {
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
				return new ResponseException(sprintf("Transfer minimum is %s IDR", number_format(self::$transfer_minimum[$transfer_instance], 2)));
			}
			$input_params['transfer_number'] = (is_numeric($input_params['transfer_number']) ? sprintf("%s", $input_params['transfer_number']) : '');
		}
		if (!isset($input_params['wallet_profile'])) {
			return false;
		}
		
		$transfer_transaction_data = array(
			'wallet_profile'			=> $input_params['wallet_profile'],
			'bank_instance'				=> array(),
		);
		
		switch ($transfer_step) {
			case 'process':
				if (!isset($transfer_transaction_data['wallet_profile']['ovo']['cash']->card_no)) {
					return false;
				}
				if (!isset($input_params['transfer_id'])) {
					return false;
				}
				$transfer_bank_inquiry_filejson = sprintf("%s%s-%s.json", 
					($this->cookies_path . DIRECTORY_SEPARATOR),
					$this->acc_num,
					$input_params['transfer_id']
				);
				
				if (!file_exists($transfer_bank_inquiry_filejson)) {
					return new ResponseException("Inquiry bank transfer file not exists.");
				}
				
				$transfer_transaction_data['collected_params'] = array();
				try {
					$inquiry_data = json_decode(@file_get_contents($transfer_bank_inquiry_filejson));
					if (!isset($inquiry_data->receiver_data)) {
						return false;
					}
					$transfer_transaction_data['collected_params']['post_params'] = [
						'bankCode'				=> (isset($inquiry_data->receiver_data->bankCode) ? sprintf('%s', $inquiry_data->receiver_data->bankCode) : ''),
						'bankName'				=> (isset($inquiry_data->receiver_data->bankName) ? sprintf("%s", trim($inquiry_data->receiver_data->bankName)) : ''),
						'accountNo'				=> (isset($transfer_transaction_data['wallet_profile']['ovo']['cash']->card_no) ? sprintf('%s', $transfer_transaction_data['wallet_profile']['ovo']['cash']->card_no) : (isset($inquiry_data->wallet_profile->ovo->cash->card_no) ? sprintf('%s', $inquiry_data->wallet_profile->ovo->cash->card_no) : '')),
						'accountName'			=> (isset($inquiry_data->receiver_data->accountName) ? sprintf('%s', $inquiry_data->receiver_data->accountName) : ''),
						'accountNoDestination'	=> (isset($inquiry_data->receiver_data->accountNo) ? sprintf('%s', $inquiry_data->receiver_data->accountNo) : ''),
						'transactionId'			=> sprintf("%s", $input_params['transfer_id']),
						'amount'				=> (isset($inquiry_data->receiver_data->baseAmount) ? sprintf("%d", $inquiry_data->receiver_data->baseAmount) : 0),
						'notes'					=> ((isset($input_params['transfer_message']) && is_string($input_params['transfer_message'])) ? substr(sprintf("%s", $input_params['transfer_message']), 0, 32) : sprintf("Transfer %s from %s", uniqid(), $this->acc_num)),
					];
					
					
					$url_api = sprintf("%s/%s", self::api_url, 'transfer/direct');
					$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
					$this->set_curl_body($transfer_transaction_data['collected_params']['post_params']);
					
					
					
					
					$transfer_transaction_data['collected_params']['curl_collect'] = $this->curlexec();
					
					if (isset($transfer_transaction_data['collected_params']['curl_collect']['http_body'])) {
						$transfer_transaction_data['collected_params']['try_transfer'] = json_decode($transfer_transaction_data['collected_params']['curl_collect']['http_body']);
						
						if (isset($transfer_transaction_data['collected_params']['try_transfer']->message) && is_string($transfer_transaction_data['collected_params']['try_transfer']->message)) {
							$transfer_transaction_data['collected_params']['try_transfer_message'] = trim(strtolower($transfer_transaction_data['collected_params']['try_transfer']->message));
							
							if ($transfer_transaction_data['collected_params']['try_transfer_message'] == 'sorry unable to handle your request') {
								$transfer_transaction_data['collected_params']['unlok_response'] = $this->unlock_transaction_id($input_params['transfer_id'], $input_params);
								if (!isset($transfer_transaction_data['collected_params']['unlok_response']['http_body']->isAuthorized)) {
									throw new ResponseException("Not have authorized unlocked transaction from api-server.");
								} else {
									if (isset($transfer_transaction_data['collected_params']['unlok_response']['post_params']['signature'])) {
										$this->headers['x-signature'] = $transfer_transaction_data['collected_params']['unlok_response']['post_params']['signature'];
										$transfer_transaction_data['collected_params']['post_params']['signature'] = $transfer_transaction_data['collected_params']['unlok_response']['post_params']['signature'];
									}
									if (is_string($transfer_transaction_data['collected_params']['unlok_response']['http_body']->isAuthorized) && (strtolower($transfer_transaction_data['collected_params']['unlok_response']['http_body']->isAuthorized) === 'true')) {
										$transfer_transaction_data['collected_params']['transfer_post_params'] = $transfer_transaction_data['collected_params']['post_params'];
										$transfer_transaction_data['collected_params']['transfer_headers'] = $this->headers;
										$transfer_transaction_data['collected_params']['transfer_url'] = sprintf("%s/%s", self::api_url, 'transfer/direct');
										
										$this->set_curl_init($transfer_transaction_data['collected_params']['transfer_url'], $this->create_curl_headers($this->headers));
										$this->set_curl_body($transfer_transaction_data['collected_params']['transfer_post_params']);
										try {
											$transfer_transaction_data['collected_params']['transfer_response'] = $this->curlexec();
											$transfer_transaction_data['collected_params']['transfer_data'] = json_decode($transfer_transaction_data['collected_params']['transfer_response']['http_body']);
										} catch (Exception $ex) {
											throw $ex;
										}
									}
								}
							}
						}
					}
				} catch (Exception $ex) {
					throw $ex;
				}
				return $transfer_transaction_data['collected_params'];
			break;
			case 'validate':
			default:
				if (isset($input_params['transfer_bank'])) {
					try {
						$transfer_bank_datas = $this->get_bank_list();
						if (count($transfer_bank_datas) == 0) {
							return new ResponseException("Failed get transfer bank instances data.");
						} else {
							foreach ($transfer_bank_datas as $b) {
								if (!empty($b['code'])) {
									array_push($transfer_transaction_data['bank_instance'], sprintf("%s", $b['code']));
								}
							}
							if (!in_array($input_params['transfer_bank'], $transfer_transaction_data['bank_instance'])) {
								return new ResponseException("Bank code not available or not supported.");
							}
							
							# Make transfer_transaction_id
							$transfer_transaction_data['transfer_transaction_inquiry'] = $this->transfer_generate_transaction_id($input_params, 'bank');
							
							if (isset($transfer_transaction_data['transfer_transaction_inquiry']['transfer_transaction_id']) && isset($transfer_transaction_data['transfer_transaction_inquiry']['payment_id']) && isset($transfer_transaction_data['transfer_transaction_inquiry']['receiver_data'])) {
								$transfer_transaction_data['transfer_transaction_id'] = $transfer_transaction_data['transfer_transaction_inquiry']['transfer_transaction_id'];
								$transfer_transaction_data['payment_id'] = $transfer_transaction_data['transfer_transaction_inquiry']['payment_id'];
								$transfer_transaction_data['receiver_data'] = $transfer_transaction_data['transfer_transaction_inquiry']['receiver_data'];
								
								unset($transfer_transaction_data['transfer_transaction_inquiry']);
							}
						}
					} catch (Exception $ex) {
						throw $ex;
					}
				}
				return $transfer_transaction_data;
			break;
		}
	}
	public function get_bank_list() {
		$url_api = sprintf("%s/%s", self::api_url, 'v1.0/reference/master/ref_bank');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body(FALSE);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		$transfer_bank_datas = array();
		if (isset($curl_collect['http_body'])) {
			$transfer_bank_instances = json_decode($curl_collect['http_body']);
			if (!isset($transfer_bank_instances->bankTypes)) {
				return new ResponseException("Unexpected response from api-server, should have bankTypes data.");
			} else {
				if (!is_array($transfer_bank_instances->bankTypes)) {
					return new ResponseException("Response bankTypes should be in array datatype.");
				} else {
					if (count($transfer_bank_instances->bankTypes) > 0) {
						foreach ($transfer_bank_instances->bankTypes as $bank) {
							array_push($transfer_bank_datas, [
								'id'			=> (isset($bank->id) ? $bank->id : 0),
								'name'			=> (isset($bank->name) ? $bank->name : ''),
								'code'			=> ((isset($bank->value) && is_string($bank->value)) ? sprintf("%s", $bank->value) : ''),
								'bank'			=> $bank
							]);
						}
					}
				}
			}
		}
		return $transfer_bank_datas;
	}
	
	private function make_transaction_id_bank(Array $input_params) {
		$post_params = [
			'actionMark'			=> (isset($input_params['actionMark']) ? sprintf("%s", $input_params['actionMark']) : self::$transfer_action_mark['bank']),
			'amount'				=> (isset($input_params['amount']) ? sprintf("%d", $input_params['amount']) : 0),
		];
		
		
		$url_api = sprintf("%s/%s", self::api_url, 'v1.0/api/auth/customer/genTrxId');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	private function get_bank_profile_data(String $token, Array $session_params, Array $input_params) {
		$this->set_authorization($token);
		if (!isset($session_params['device_id']) || !isset($session_params['push_notif_id'])) {
			return false;
		}
		
		if (!isset($input_params['wallet_profile']['ovo']['cash']->card_no)) {
			return false;
		}
		
		$post_params		= array(
			'accountNo'				=> (isset($input_params['transfer_number']) ? $input_params['transfer_number'] : ''),
			'amount'				=> (isset($input_params['transfer_amount']) ? sprintf("%d", $input_params['transfer_amount']) : 0),
			'bankCode'				=> (isset($input_params['transfer_bank']) ? $input_params['transfer_bank'] : ''),
			'messages'				=> (isset($input_params['']) ? $input_params[''] : ''),
		);
		if ($post_params['amount'] < self::$transfer_minimum['bank']) {
			return new ResponseException(sprintf("Minimum transfer amount to bank is: %s.", self::$transfer_minimum['bank']));
		}
		$url_api = sprintf("%s/%s", self::api_url, 'transfer/inquiry/');
		$this->set_curl_init($url_api, $this->create_curl_headers($this->headers));
		$this->set_curl_body($post_params);
		
		try {
			$curl_collect = $this->curlexec();
		} catch (Exception $ex) {
			throw $ex;
		}
		if (isset($curl_collect['http_body'])) {
			$http_body = json_decode($curl_collect['http_body']);
			return $http_body;
		}
		return false;
	}
	//-----------------------------------------------------------------------------------------------------------------------
	public function curlexec() {
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
	private function set_curl_body($post_params = FALSE) {
		if ($post_params === FALSE) {
			curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($this->ch, CURLOPT_POST, FALSE);
			curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		} else {
			$post_data = '';
			if (is_array($post_params)) {
				$post_data = json_encode($post_params);
			} else if (is_object($post_params)) {
				$post_data = json_encode($post_params);
			} else if (is_string($post_params) || is_numeric($post_params)) {
				$post_data = sprintf("%s", $post_params);
			} else {
				$post_data = '{}';
			}
			curl_setopt($this->ch, CURLOPT_HTTPGET, FALSE);
			curl_setopt($this->ch, CURLOPT_POST, TRUE);
			curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post_data);
		}
	}
	private function set_curl_body_with_integer_check($post_params = FALSE) {
		if ($post_params === FALSE) {
			curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($this->ch, CURLOPT_POST, FALSE);
			curl_setopt($this->ch, CURLOPT_HTTPGET, TRUE);
		} else {
			$post_data = '';
			if (is_array($post_params)) {
				$post_data = json_encode($post_params, JSON_NUMERIC_CHECK);
			} else if (is_object($post_params)) {
				$post_data = json_encode($post_params, JSON_NUMERIC_CHECK);
			} else if (is_string($post_params) || is_numeric($post_params)) {
				$post_data = trim($post_params);
			} else {
				$post_data = '{}';
			}
			curl_setopt($this->ch, CURLOPT_HTTPGET, FALSE);
			curl_setopt($this->ch, CURLOPT_POST, TRUE);
			curl_setopt($this->ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($this->ch, CURLOPT_POSTFIELDS, $post_data);
		}
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






























