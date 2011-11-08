HP_BlackList
===========

HP_BlackList provides a PHP class which checks IP addresses against Project Honey Pot's http:BL (black list). 


Features
--------

* Wraps the Project Honey Pot's API queries in simple to use OO class
* Returns an object populated with the results of the query 


Methods
-------

* **allow($ip)** - [Static] Returns true if the passed in IP address passed the thresholds set, or false on failure. Adjust $threatThreshold and $typeBitThreshold to adjust this method's sensitivity. On error this method assumes the IP should be allowed.
* **check($ip)** - [Static] Checks the IP against the black list and returns an object of HP_BlackListResult populated with the returned information. On error this method assumes the IP should be allowed.


Configuation
----------

* Add your http:BL API key to the class const HP_API_KEY. If you do not have an API key already you can sign up for one (free) here: 
http://www.projecthoneypot.org/httpbl_configure.php 

(If you would prefer to save the API key to a configuration file somewhere else, you can use the getAPIKey() method to retrieve that value.)


Example Use
----------

A simple test whether or not to allow the current user to do some action:

	require_once(HP_BlackList.class.php);
	
	if(!HP_BlackList::allow($_SERVER['REMOTE_ADDR'])) {
		die('not allowed');
	}

Block only harvesters

	require_once(HP_BlackList.class.php);
	
	$blr = HP_BlackList::check($_SERVER['REMOTE_ADDR']);
	if(in_array($blr->typeArray, HP_BlackList::TYPE_HARVESTER)) {
		die('no harvesters');
	}


Find only Google search crawlers:

	require_once(HP_BlackList.class.php);
	
	$blr = HP_BlackList::check($_SERVER['REMOTE_ADDR']);
	if( $blr->searchEngineType == 'Google' ) {
		echo "Hello google!";
	}
