<?php
/**
  *
  * Self-contained class that creates reasonably secure URLs with an expiration.
  *
  * URLs are signed with hash signature that includes an exiration time. 
  *
  * USAGE: 
  *
  * Sign a URL: 
  *
  * include( 'class-url-signer.php' );
  * $signer::sign( 'https://somedomainname.nul', '5 HOURS' );
  *
  * Verify a URL's signature
  *
  * include( 'class-url-signer.php' );
  * $result = $signer::verify( 'https://somedomainname.nul/?expires=xxxx&signature=xxxx' ); 
  *
  * $result will be true or false
  * 
  */
class Custom_URL_Signer { 

	// *** Define a secret key, used to create the signature ***
	private static $key = 'Your complicated really long secret key goes here!';
	
	// Your GMT offset, helpful for getting the time in the correct timezone 
	private static $gmt_offset = '-5';
	
	// Used by the current_time() method in this class
	private static $hour_in_seconds = 84600;
	
	// A default URL validity period. URLs older than this fail verification
	private static $expires_in = '5 HOURS'; // Standard PHP strtotime() notation. 
	
	/**
	  *
	  * Sign a URL and return it with two new params appended: "expires" and "signature"
	  *
	  * @param string $url The URL to sign
	  * @param string $expires An optional expiration time period in strtotime() notation (e.g. '5 HOURS', '3 DAYS', etc)
	  *
	  * @return string Signed URL 
	  *
	  */
	public static function sign( $url, $expires = '' ) { 
	
		// Use default expiration if none passed to this method
		if ( empty( $expires ) )
			$expires = self::$expires_in;

		$time = self::current_time( 'timestamp' );

		$expire_timestamp = strtotime( '+' . $expires, $time );
		
		// build a signature hash string
		$signature = hash_hmac( 'sha256', $expire_timestamp . '::' . $url . '::' . self::$key, self::$key );

		// append the hash and expiration time to the url and return it
		return self::add_query_arg( array( 'expires' => $expire_timestamp, 'signature' => $signature ), $url );
	}
	
	/**
	  *
	  * Verify a URL signature. 
	  *
	  * @param string $url The URL to verify 
	  *
	  * @return bool Returns true if the signature is valid and not expired, otherwise false
	  *
	  */
	public static function verify( $url ) { 
		
		// parse the url, we need the query parts
		$parts = parse_url( $url  );

		if ( empty( $parts[ 'query' ] ) ) 
			return false; 
			
		// get query parts into an array 
		$args = self::parse_args( $parts['query'] );

		// No args? Then the URL isn't valid, it should have "expires" and "signature" query vars. 
		if ( empty( $args ) )
			return false; 

		// find the expires value
		$expires = isset( $args['expires'] ) ? $args['expires'] : false; 
		
		// find the signature value 
		$signature = isset( $args['signature'] ) ? $args['signature'] : false; 
		
		if ( empty( $expires ) || empty( $signature ) || intval( $expires ) <= 0 )
			return false; 
		
		$time = self::current_time( 'timestamp' ); // GMT
		
		if ( $expires < $time ) 
			return false; 
		
		// Remove expires and signature args and rebuild the URL without them to compare against the original URL used to generate the hash
		unset( $args[ 'expires'] );		
		unset( $args[ 'signature'] );

		$args2 = array();
		
		foreach( $args as $k => $v ) 
			$args2[] = $k . '=' . $v;
			
		$args = implode( '&', $args2 );
		
		if ( !isset( $parts['path'] ) )
			$parts['path'] = '';
			
		// Put the URL back together without expires and signature 
		$url = $parts['scheme'] . '://' . $parts['host'] . $parts['path'];
		
		if ( !empty( $args ) ) 
			$url .= '?' . $args;

		// Get a hash of what we expect the query's signature (hash) to be
		$expected = hash_hmac( 'sha256', $expires . '::' . $url . '::' . self::$key, self::$key );

		// Test if we have what we expect
		// Use hash_equals to avoid certain security issues
		$result = hash_equals( $expected, $signature );

		return $result;
	}
	
	// ALL METHODS BELOW ARE FROM WORDPRESS CORE CODE
	// Included in this class to make it self-contained and not dependant on external code
	
	/**
	* Parses a string into variables to be stored in an array.
	*
	* Uses {@link https://secure.php.net/parse_str parse_str()} and stripslashes if
	* {@link https://secure.php.net/magic_quotes magic_quotes_gpc} is on.
	*
	* 
	*
	* @param string $string The string to be parsed.
	* @param array  $array  Variables will be stored in this array.
	*/
	private static function parse_str( $string, &$array ) {
		parse_str( $string, $array );
		if ( get_magic_quotes_gpc() )
			$array = stripslashes_deep( $array );
	}
	
	/**
	* Merge user defined arguments into defaults array.
	*
	* This function is used to allow for both string or array
	* to be merged into another array.
	*
	* @param string|array|object $args     Value to merge with $defaults.
	* @param array               $defaults Optional. Array that serves as the defaults. Default empty.
	* @return array Merged user defined values with defaults.
	*/
	public static function parse_args( $args, $defaults = '' ) {
		if ( is_object( $args ) )
			$r = get_object_vars( $args );
		elseif ( is_array( $args ) )
			$r =& $args;
		else
			self::parse_str( $args, $r );

		if ( is_array( $defaults ) )
			return array_merge( $defaults, $r );
		return $r;
	}

	/**
	* Retrieves a modified URL query string.
	*
	* You can rebuild the URL and append query variables to the URL query by using this function.
	* There are two ways to use this function; either a single key and value, or an associative array.
	*
	* Using a single key and value:
	*
	*     add_query_arg( 'key', 'value', 'http://example.com' );
	*
	* Using an associative array:
	*
	*     add_query_arg( array(
	*         'key1' => 'value1',
	*         'key2' => 'value2',
	*     ), 'http://example.com' );
	*
	* Omitting the URL from either use results in the current URL being used
	* (the value of `$_SERVER['REQUEST_URI']`).
	*
	* Values are expected to be encoded appropriately with urlencode() or rawurlencode().
	*
	* Setting any query variable's value to boolean false removes the key (see remove_query_arg()).
	*
	* Important: The return value of add_query_arg() is not escaped by default. Output should be
	* late-escaped with esc_url() or similar to help prevent vulnerability to cross-site scripting
	* (XSS) attacks.
	*
	*
	* @param string|array $key   Either a query variable key, or an associative array of query variables.
	* @param string       $value Optional. Either a query variable value, or a URL to act upon.
	* @param string       $url   Optional. A URL to act upon.
	* @return string New URL query string (unescaped).
	*/
	private static function add_query_arg() {
		$args = func_get_args();
		if ( is_array( $args[0] ) ) {
			if ( count( $args ) < 2 || false === $args[1] )
					$uri = $_SERVER['REQUEST_URI'];
			else
					$uri = $args[1];
		} else {
			if ( count( $args ) < 3 || false === $args[2] )
					$uri = $_SERVER['REQUEST_URI'];
			else
					$uri = $args[2];
		}

		if ( $frag = strstr( $uri, '#' ) )
			$uri = substr( $uri, 0, -strlen( $frag ) );
		else
			$frag = '';

		if ( 0 === stripos( $uri, 'http://' ) ) {
			$protocol = 'http://';
			$uri = substr( $uri, 7 );
		} elseif ( 0 === stripos( $uri, 'https://' ) ) {
			$protocol = 'https://';
			$uri = substr( $uri, 8 );
		} else {
			$protocol = '';
		}

		if ( strpos( $uri, '?' ) !== false ) {
			list( $base, $query ) = explode( '?', $uri, 2 );
			$base .= '?';
		} elseif ( $protocol || strpos( $uri, '=' ) === false ) {
			$base = $uri . '?';
			$query = '';
		} else {
			$base = '';
			$query = $uri;
		}

		self::parse_str( $query, $qs );
		$qs = self::urlencode_deep( $qs ); // this re-URL-encodes things that were already in the query string
		if ( is_array( $args[0] ) ) {
			foreach ( $args[0] as $k => $v ) {
					$qs[ $k ] = $v;
			}
		} else {
			$qs[ $args[0] ] = $args[1];
		}
		
		foreach ( $qs as $k => $v ) {
			if ( $v === false )
					unset( $qs[$k] );
		}

		$ret = self::build_query( $qs );
		$ret = trim( $ret, '?' );
		$ret = preg_replace( '#=(&|$)#', '$1', $ret );
		$ret = $protocol . $base . $ret . $frag;
		$ret = rtrim( $ret, '?' );
		return $ret;
	}
	
	/**
	* Navigates through an array, object, or scalar, and encodes the values to be used in a URL.
	*
	* @param mixed $value The array or string to be encoded.
	* @return mixed $value The encoded value.
	*/
	private static function urlencode_deep( $value ) {
		return self::map_deep( $value, 'urlencode' );
	}

	/**
	* Maps a function to all non-iterable elements of an array or an object.
	*
	* This is similar to `array_walk_recursive()` but acts upon objects too.
	*
	*
	* @param mixed    $value    The array, object, or scalar.
	* @param callable $callback The function to map onto $value.
	* @return mixed The value with the callback applied to all non-arrays and non-objects inside it.
	*/
	public static function map_deep( $value, $callback ) {
		if ( is_array( $value ) ) {
			foreach ( $value as $index => $item ) {
					$value[ $index ] = self::map_deep( $item, $callback );
			}
		} elseif ( is_object( $value ) ) {
			$object_vars = get_object_vars( $value );
			foreach ( $object_vars as $property_name => $property_value ) {
					$value->$property_name = self::map_deep( $property_value, $callback );
			}
		} else {
			$value = call_user_func( $callback, $value );
		}

		return $value;
	}


	/**
	* Navigates through an array, object, or scalar, and removes slashes from the values.
	*
	*
	* @param mixed $value The value to be stripped.
	* @return mixed Stripped value.
	*/
	private static function stripslashes_deep( $value ) {
		return self::map_deep( $value, 'stripslashes_from_strings_only' );
	}

	/**
	* Callback function for `stripslashes_deep()` which strips slashes from strings.
	*
	*
	* @param mixed $value The array or string to be stripped.
	* @return mixed $value The stripped value.
	*/
	private static function stripslashes_from_strings_only( $value ) {
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}


	/**
	* Build URL query based on an associative and, or indexed array.
	*
	* This is a convenient function for easily building url queries. It sets the
	* separator to '&' and uses _http_build_query() function.
	*
	*
	* @see _http_build_query() Used to build the query
	* @link https://secure.php.net/manual/en/function.http-build-query.php for more on what
	*               http_build_query() does.
	*
	* @param array $data URL-encode key/value pairs.
	* @return string URL-encoded string.
	*/
	private static function build_query( $data ) {
		return self::_http_build_query( $data, null, '&', '', false );
	}

	/**
	* From php.net (modified by Mark Jaquith to behave like the native PHP5 function).
	*
	* @access private
	*
	* @see https://secure.php.net/manual/en/function.http-build-query.php
	*
	* @param array|object  $data       An array or object of data. Converted to array.
	* @param string        $prefix     Optional. Numeric index. If set, start parameter numbering with it.
	*                                  Default null.
	* @param string        $sep        Optional. Argument separator; defaults to 'arg_separator.output'.
	*                                  Default null.
	* @param string        $key        Optional. Used to prefix key name. Default empty.
	* @param bool          $urlencode  Optional. Whether to use urlencode() in the result. Default true.
	*
	* @return string The query string.
	*/
	private static function _http_build_query( $data, $prefix = null, $sep = null, $key = '', $urlencode = true ) {
		$ret = array();

		foreach ( (array) $data as $k => $v ) {
			if ( $urlencode)
					$k = urlencode($k);
			if ( is_int($k) && $prefix != null )
					$k = $prefix.$k;
			if ( !empty($key) )
					$k = $key . '%5B' . $k . '%5D';
			if ( $v === null )
					continue;
			elseif ( $v === false )
					$v = '0';

			if ( is_array($v) || is_object($v) )
					array_push($ret,self::_http_build_query($v, '', $sep, $k, $urlencode));
			elseif ( $urlencode )
					array_push($ret, $k.'='.urlencode($v));
			else
					array_push($ret, $k.'='.$v);
		}

		if ( null === $sep )
			$sep = ini_get('arg_separator.output');

		return implode($sep, $ret);
	}
	
	/**
	* Retrieve the current time based on specified type.
	*
	* The 'mysql' type will return the time in the format for MySQL DATETIME field.
	* The 'timestamp' type will return the current timestamp.
	* Other strings will be interpreted as PHP date formats (e.g. 'Y-m-d').
	*
	* If $gmt is set to either '1' or 'true', then both types will use GMT time.
	* if $gmt is false, the output is adjusted with the GMT offset as defined in this class
	*
	* @param string   $type Type of time to retrieve. Accepts 'mysql', 'timestamp', or PHP date
	*                       format string (e.g. 'Y-m-d').
	* @param int|bool $gmt  Optional. Whether to use GMT timezone. Default false.
	* @return int|string Integer if $type is 'timestamp', string otherwise.
	*/
	private static function current_time( $type, $gmt = 0 ) {
		switch ( $type ) {
			case 'mysql':
					return ( $gmt ) ? gmdate( 'Y-m-d H:i:s' ) : gmdate( 'Y-m-d H:i:s', ( time() + ( self::$gmt_offset * self::$hour_in_seconds ) ) );
			case 'timestamp':
					return ( $gmt ) ? time() : time() + ( self::$gmt_offset * self::$hour_in_seconds );
			default:
					return ( $gmt ) ? date( $type ) : date( $type, time() + ( self::$gmt_offset * self::$hour_in_seconds ) );
		}
	}

}

/**** 
// Simple test code: 

$signer = new Custom_URL_Signer;

// sign a URL 
$url = $signer::sign( 'http://google.com?file=123&blah=that-stuff' );

// Show it
echo $url . "\n\n";

// Wait 3 seconds just grins 
sleep( 3 );

// Verify the signed URL 
$result = $signer::verify( $url );

// Show result 
var_dump( $result );

echo "\n\n";

exit;

***/ 
