<?php
/**
 * Check an IP against Project Honey Pot's API
 * 
 * For more information on project honeypot see: 
 * http://www.projecthoneypot.org/httpbl_api.php 
 *
 * 
 * @author Graham McNicoll (http://www.education.com/)
 * @version 1.0
 * @copyright Copyright (c) 2011, Education.com
 * @license http://www.opensource.org/licenses/mit-license.php MIT License
 *
 */
class HP_BlackList {
	
	/**
	 * Enter your API key here. 
	 * If you do not already have one, you can sign up here: 
	 * http://www.projecthoneypot.org/httpbl_configure.php
	 */
	const HP_API_KEY = '<add your key here>';
	
    // The DNS query domain: 
	const HP_API_DOMAIN = 'dnsbl.httpbl.org';
	
	/**
	 *  The following are english representations of the 
     *  responses from the query:
	 */
	const TYPE_NOT_BLACKLISTED = 'Not Blacklisted';
	const TYPE_SEARCH_ENGINE = 'Search Engine';
	const TYPE_SUSPICIOUS = 'Suspicious';
	const TYPE_HARVESTER = 'Harvester';
	const TYPE_COMMENT_SPAMMER = 'Comment Spammer';
	
	//the 4th octect bitset:
	const HP_BIT_SEARCH_ENGINE = 0;
	const HP_BIT_SUSPICIOUS = 1;
	const HP_BIT_HARVESTER = 2;
	const HP_BIT_COMMENT_SPAMMER = 4;
	
    // code -> english name
	private static $searchEngineMap = array(
		0	=> 	'Uncodumented',
		1	=>	'AltaVista',
		2	=>	'Ask',
		3	=>	'Baidu',
		4	=>	'Excite',
		5	=>	'Google',
		6	=>	'Looksmart',
		7	=>	'Lycos',
		8	=>	'MSN',
		9	=>	'Yahoo',
		10	=>	'Cuil',
		11	=>	'InfoSeek',
		12	=>	'Miscellaneous'
	);
	
	/**
	 * Default thresholds as used by the allow method below
	 */
	public static $threatThreshold = 20; //http://www.projecthoneypot.org/threat_info.php
	public static $typeBitThreshold = 2; //harvester and above.
	
	
	/**
	 * Checks an IP against the blacklist and returns true or false if the ip should be allowed
	 * Adjust static properties threatThreshold and typeBitThreshold to change sensitivity.
	 *
	 * @param string $ip - The IP address to check
	 * @return boolean
	 */
	public static function allow($ip) {
		$blr = self::check($ip);
		if($blr->threat >= self::$threatThreshold && $blr->typeBit >= self::$typeBitThreshold) {
			return false;
		}
		return true;
	}
	
	/**
	 * Checks an IP address against the blacklist. 
	 *
	 * @param string $ip - The IP address to check
	 * @return HP_BlackListResult
	 */
	public static function check($ip) {
        
		$reversedIp = implode('.', array_reverse(explode('.', $ip)));
		$lookup = self::getAPIKey().'.'.$reversedIp.'.'.self::HP_API_DOMAIN;
		$rawResult = gethostbyname($lookup); //this function returns $lookup on lookup failure.
		$result = explode('.', $rawResult);

		$blr = new HP_BlackListResult();
		
		$blr->ip = $ip;
		//set initially to safe:
		$blr->typeArray = array(self::TYPE_NOT_BLACKLISTED);
		$blr->threat = 0;
		
        // On failure, gethostbyname() returns the hostname which was looked up:
        
		if (!empty($result) && $rawResult != $lookup && $result[0] == 127) {
            
			//query worked, parse for results:
			$blr->activity = $result[1]; 				//days since last activity
			$blr->threat = $result[2];					//threat score, 0 to 255, 255 being the most 'threatening'
			$blr->typeBit = $typebit = $result[3];		//type
			
			$blr->typeArray = array();
			
			if($typebit & self::HP_BIT_SEARCH_ENGINE) {
				$blr->typeArray[] = self::TYPE_SEARCH_ENGINE;
				$blr->threat = 0; //Search engine results are special, they encode the search engine type as the third octet.
				$blr->activity = null; //Search engine results are special, nothing is encoded in the second octet.
				$blr->searchEngineTypeCode = $result[2];
				$blr->searchEngineType = (isset(self::$searchEngineMap[$blr->searchEngineTypeCode]))?self::$searchEngineMap[$blr->searchEngineTypeCode]:'Unknown';
			} else {
				if($typebit & self::HP_BIT_SUSPICIOUS) 			$blr->typeArray[] = self::TYPE_SUSPICIOUS;
				if($typebit & self::HP_BIT_HARVESTER) 			$blr->typeArray[] = self::TYPE_HARVESTER;
				if($typebit & self::HP_BIT_COMMENT_SPAMMER) 	$blr->typeArray[] = self::TYPE_COMMENT_SPAMMER;
			}
			
		}
		return $blr;
	}
    
    private static function getAPIKey() {
        return self::HP_API_KEY;
    }
}
    
/**
 * HP_BlackListResult is an object which holds 
 * the result of the HTTP:BL request
 */
class HP_BlackListResult {
	public $ip;
	public $activity;
	public $threat;
	public $typeBit;
	public $typeArray;
	public $searchEngineType;
	public $searchEngineTypeCode;
}
?>