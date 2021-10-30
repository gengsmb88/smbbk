<?php
namespace Smbbk\Id\Ovo;
use \Exception;
class ResponseException extends Exception {
	
	public $msg_string = '';
	function __construct(String $msg_string) {
		parent::__construct();
		$this->msg_string = $msg_string;
	}

}