<?php

// import our library
require_once( dirname( __FILE__ ) . '/inc/libraries/GShoppingContent.php' );

/**
 * WP HTTP API Response
 *
 * Abstracts the WP HTTP API result to suit _GSC_Response
 *
 * @package GShoppingContent
 * @version 1.3
 * @author niall.campbell@gmail.com
 **/
class _WPGSC_Response extends _GSC_Response
{
	/**
	 * Create a new _WPGSC_Response instance.
	 *
	 * @param array $result The result from WP HTTP API after making a request.
	 * @author niall.campbell@gmail.com
	 **/
	function __construct($result)
	{
		$info = array(
			'http_code'    => $result['response']['code'],
			'content_type' => $result['headers']['content_type']
		);
		$body = $result['body'];
		parent::__construct($info, $body);
	}

}

/**
 * WP HTTP client
 *
 * A thin wrapper around WP HTTP API to ease the repetitive tasks such as adding
 * Authorization headers.
 *
 * This class is entirely static, and all functions are designed to be used
 * statically. It maintains no state.
 *
 * @package GShoppingContent
 * @version 1.3
 * @author afshar@google.com, dhermes@google.com, niall.campbell@gmail.com
 * @copyright Niall Campbell, 2013
 **/
class _WPGSC_Http extends _GSC_Http
{
	/**
	 * Make an unsigned HTTP GET request.
	 *
	 * @param string $uri The URI to request.
	 * @return _WPGSC_Response The response to the request or WP_Error on fail.
	 **/
	public static function unsignedGet( $uri ) {
		$args = array(
			'sslverify' => false
		);
		
		$result = wp_remote_get( $uri , $args );
		
		if( is_wp_error( $result ) ) {
			$result = self::wpErrorToResponse( $result );
		}

		return new _WPGSC_Response( $result );
	}
	
	/**
	 * Make an HTTP GET request with a Google Authorization header.
	 *
	 * @param string $uri The URI to request.
	 * @param _GSC_Token $token The authorization token.
	 * @return _GSC_Response The response to the request.
	 **/
	public static function get( $uri, $token ) {
		$args = array(
			'sslverify' => false
		);
		
		return $token->makeWPAuthenticatedRequest( $uri, $args );
	}
	
	/**
	 * Post fields as an HTTP form.
	 *
	 * @param string $uri The URI to post to.
	 * @param array $fields The form fields to post.
	 * @param array $headers The headers. Defaults to null.
	 * @return _GSC_Response The response to the request.
	 **/
	public static function postForm( $uri, $fields, $headers=null ) {	
		$args = array(
			'body' => $fields,
			'sslverify' => false
		);
		
		if( $headers != null ) {
			$args['headers'] = $headers;	
		}
		
		$result = wp_remote_post( $uri, $args );
		
		if( is_wp_error( $result ) ) {
			$result = self::wpErrorToResponse( $result );
		}
		
		return new _WPGSC_Response( $result );
	}
	
	/**
	 * Make an HTTP POST request with a Google Authorization header.
	 *
	 * @param string $uri The URI to post to.
	 * @param string $data The data to post.
	 * @param _GSC_Token $token The authorization token.
	 * @return _GSC_Response The response to the request.
	 **/
	public static function post( $uri, $data, $token ) {
		$args = array(
			'method' => 'POST',
			'redirection' => 0,
			'body' => $data,
			'sslverify' => false
		);
		
		return $token->makeWPAuthenticatedRequest( $uri, $args );
	}
	
	/**
	 * Make an HTTP PUT request with a Google Authorization header.
	 *
	 * @param string $uri The URI to post to.
	 * @param string $data The data to post.
	 * @param _GSC_Token $token The authorization token.
	 * @return _GSC_Response The response to the request.
	 **/
	public static function put( $uri, $data, $token ) {		
		$args = array(
			'method' => 'PUT',
			'body' => $data,
			'sslverify' => false
		);
		
		return $token->makeWPAuthenticatedRequest( $uri, $args );
	}
	
	/**
	 * Make an HTTP DELETE request with a Google Authorization header.
	 *
	 * @param string $uri The URI to post to.
	 * @param _GSC_Token $token The authorization token.
	 * @return _GSC_Response The response to the request.
	 **/
	public static function delete( $uri, $token ) {		
		$args = array(
			'method' => 'DELETE',
			'sslverify' => false
		);
		
		return $token->makeWPAuthenticatedRequest( $uri, $args );
	}
	
	/**
	 * Generate a Response error from a WP_Error object.
	 *
	 * @param WP_Error $wperror The error from a WP HTTP API request.
	 * @return object that mimmicks the form of a API Error Response
	 **/	
	public static function wpErrorToResponse($wperror) {
		$error_code = $wperror->get_error_code();
		switch ($error_code) {
			case 'http_request_failed' : $error_int = 1; break;
			case 'http_failure' :        $error_int = 2; break;
			default :                    $error_int = 0; break;
		}
		$errorMsg = 'Invalid response ' . $error_code . '.';
		
		$errorDict = $wperror->get_error_message( $error_code );
		if( ! empty ( $errorDict ) )
			$errorMsg = $errorDict;
			
		$response = array(
			'response' => array('code' => $error_int),
			'headers'  => array('content_type' => ''),
			'body'     => json_encode( array( 'error' => $errorMsg ) )
		);
		
		return $response;
	}
}

/**
 * Extends Client Login requests to use WP HTTP API
 *
 * @package GShoppingContent
 * @version 1.3
 **/
class WPGSC_ClientLoginToken extends GSC_ClientLoginToken
{

	/**
	 * Log in to ClientLogin.
	 *
	 * @static
	 * @param string $email Google account email address.
	 * @param string $password Google account password.
	 * @param string $userAgent The user agent. Describes application.
	 *						  Defaults to constant string USER_AGENT.
	 * @return string The Auth token from ClientLogin.
	 * @author afshar@google.com, dhermes@google.com, niall.campbell@gmail.com
	 **/
	public static function login( $email, $password, $userAgent=USER_AGENT )
	{
		$fields = array(
			'Email' => $email,
			'Passwd' => $password,
			'service' => CLIENTLOGIN_SVC,
			'source' => $userAgent,
			'accountType' => 'GOOGLE'
		);
		$resp = _WPGSC_Http::postForm( CLIENTLOGIN_URI, $fields );

		$tokens = array();
		foreach ( explode( "\n", $resp->body ) as $line ) {
			$line = chop( $line );
			if ( $line ) {
				list( $key, $val ) = explode( '=', $line, 2 );
				$tokens[ $key ] = $val;
			}
		}
		return new WPGSC_ClientLoginToken( $tokens['Auth'] );
	}
	
	/**
	 * Makes an authenticated request.
	 *
	 * @param $uri the uri to request
	 * @param $args the WP HTTP API arguments
	 * @return _GSC_Response The response to the request.
	 **/
	public function makeWPAuthenticatedRequest( $uri, $args ) {
		$headers = array(
			'Content-Type'  => 'application/atom+xml',
			'Authorization' => $this->getTokenString()
		);
		$args['headers'] = wp_parse_args( $headers, $args['headers'] );
		
		$result = wp_remote_request( $uri, $args );
		
		if( is_wp_error( $result ) )
			$result = _WPGSC_Http::wpErrorToResponse( $result );
			
		return new _WPGSC_Response( $result );
	}
}

/**
 * Extends GSC_OAuth2Token to use WP HTTP API
 *
 * @package GShoppingContent
 * @version 1.3
 **/
class WPGSC_OAuth2Token extends GSC_OAuth2Token
{
    /**
     * Client ID for the application.
     *
     * @var string
     **/
    private $clientId;

    /**
     * Client secret for the application.
     *
     * @var string
     **/
    private $clientSecret;

    /**
     * User agent for request headers. Describes application.
     *
     * @var string
     **/
    private $userAgent;

    /**
     * Token used to access user data.
     *
     * @var string
     **/
    private $accessToken;

    /**
     * Token used to refresh access token.
     *
     * @var string
     **/
    private $refreshToken;

    /**
     * Redirect URI for after authorization occurs.
     *
     * @var string
     **/
    private $redirectUri;

    /**
     * Flag to determine if the access token is valid.
     *
     * @var boolean
     **/
    private $invalid;	
	/**
	 * Datetime used to determine when the access token will expire
	 *
	 * @var int
	 **/
	private $expiryTime;

    /**
     * Create a new GSC_OAuth2Token instance.
     *
     * @param string $clientId The client ID for the token.
     * @param string $clientSecret The client secret for the token.
     * @param string $redirectUri The redirect URI.
     * @param string $userAgent The user agent. Describes application.
     **/
    function __construct($clientId, $clientSecret, $redirectUri, $userAgent)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
        $this->userAgent = $userAgent;
        $this->invalid = false;
        $this->scope = OAUTH_SCOPE;
    }

	/**
	 * Create a blob encapsulating the token information.
	 *
	 * @return string Blob containing token data.
	 **/
	public function toBlob() {
		$tokenParts = array(
			$this->clientId,
			$this->clientSecret,
			$this->userAgent,
			$this->accessToken,
			$this->refreshToken,
			$this->redirectUri,
			$this->expiryTime
		);

		return implode('|', $tokenParts);
	}

	/**
	 * Create a token from a blob.
	 *
	 * @param string $blob Blob containing token data.
	 * @return WPGSC_OAuth2Token Token built from blob.
	 * @author dhermes@google.com, niall.campbell@gmail.com
	 **/
	public function fromBlob($blob) {
		$tokenParts = explode('|', $blob);

		if (count($tokenParts) != 7) {
			throw new GSC_TokenError('Blob contains wrong number of parts.');
		}

		$this->clientId = $tokenParts[0] ? $tokenParts[0] : null;
		$this->clientSecret = $tokenParts[1] ? $tokenParts[1] : null;
		$this->userAgent = $tokenParts[2] ? $tokenParts[2] : null;
		$this->accessToken = $tokenParts[3] ? $tokenParts[3] : null;
		$this->refreshToken = $tokenParts[4] ? $tokenParts[4] : null;
		$this->redirectUri = $tokenParts[5] ? $tokenParts[5] : null;
		$this->expiryTime = $tokenParts[6] ? $tokenParts[6] : null;

		return $this;
	}
	

	/**
	 * Extract tokens from a response body.
	 *
	 * @param string $body The response body to be parsed.
	 * @return void
	 **/
	private function extractTokens($body) {
		$bodyDict = json_decode($body, true);
		// Will throw error if access_token not returned
		$this->accessToken = $bodyDict['access_token'];
		if (array_key_exists('refresh_token', $bodyDict)) {
			$this->refreshToken = $bodyDict['refresh_token'];
		}
		
		if (array_key_exists('expires_in', $bodyDict)) {
			$this->expiryTime = time() + $bodyDict['expires_in'];
		}
	}

	/**
	 * Refresh the access token.
	 *
	 * @return _GSC_Response The response to the refresh request.
	 * @throws GSC_TokenError if the response code is not 200.
	 **/
	private function refresh() {
		$body = array(
			'grant_type' => 'refresh_token',
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'refresh_token' => $this->refreshToken
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
			'user-agent'   => $this->userAgent
		);

		$urlEncodedBody = http_build_query( $body );
		$resp = _WPGSC_Http::postForm( TOKEN_URI, $urlEncodedBody, $headers );

		if ($resp->code == 200) {
			$this->extractTokens( $resp->body );
		}
		else {
			$this->invalid = true;
			self::raiseFromJson( $resp );
		}

		return $resp;
	}
	
    /**
     * Generate a URI to redirect to the provider.
     *
     * @param string $approvalPrompt Value that determines if user will be
     *                               prompted to give approval. Defaults to
     *                               'auto' but 'force' is also valid.
     * @param string $redirectUri Either the string 'urn:ietf:wg:oauth:2.0:oob'
     *                            for a non-web-based application, or a URI
     *                            that handles the callback from the
     *                            authorization server.
     * @param string $responseType Either the string 'code' for server-side
     *                             or native application, or the string 'token'
     *                             for client-side application.
     * @param string $accessType Either the string 'offline' to request a
     *                           refresh token or 'online'.
     * @return string The URI to redirect to.
     **/
    public function generateAuthorizeUrl(
        $redirectUri='urn:ietf:wg:oauth:2.0:oob',
        $approvalPrompt='auto',
        $responseType='code',
        $accessType='offline') {
        $this->redirectUri = $redirectUri;

        $query = array(
            'response_type' => $responseType,
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $this->scope,
            'approval_prompt' => $approvalPrompt,
            'access_type' => $accessType
        );

        return AUTH_URI . '?' . http_build_query($query);
    }
	
	/**
	 * Raise an error from a JSON response object.
	 *
	 * @param _GSC_Response $response The response to some request.
	 * @throws GSC_TokenError with contents gleaned from response.
	 * @return void
	 **/
	private static function raiseFromJson( $response ) {
		$errorMsg = 'Invalid response ' .  $response->code . '.';

		$errorDict = json_decode( $response->body, true );
		if ($errorDict != null) {
			if ( array_key_exists('error', $errorDict ) ) {
				$errorMsg = $errorDict['error'];
			}
		}

		throw new GSC_TokenError( $errorMsg, $response->code );
	}
	
	/**
	 * Exchanges a code for an access token.
	 *
	 * @param string|array $code A string or array with 'code' as a key. This
	 *						   code can be exchanged for an access token.
	 * @return WPGSC_OAuth2Token The current token (this) after access token
	 *						 is retrieved and set.
	 * @throws GSC_TokenError if the response code is not 200.
	 **/
	public function getAccessToken( $code ) {
		if ( !( is_string( $code ) ) ) {
			$code = $code['code'];
		}

		$body = array(
			'grant_type'    => 'authorization_code',
			'client_id'     => $this->clientId,
			'client_secret' => $this->clientSecret,
			'code'          => $code,
			'redirect_uri'  => $this->redirectUri,
			'scope'         => $this->scope
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
			'user-agent'   => $this->userAgent
		);

		$urlEncodedBody = http_build_query( $body );
		$resp = _WPGSC_Http::postForm( TOKEN_URI, $urlEncodedBody, $headers );

		if ( $resp->code == 200 ) {
			$this->extractTokens( $resp->body );
			return $this;
		}
		else {
			self::raiseFromJson( $resp );
		}
	}

	/**
	 * Returns the time to expiry in seconds
	 *
	 * @return time remaining for access token
	 **/		
	public function getTimeToExpiry() {
		return $this->expiryTime - time();
	}
	
	/**
	 * Refresh the access token if expired
	 *
	 * @return WPGSC_OAuth2Token The current token (this) after access token
	 *						 is retrieved and set.
	 * @throws GSC_TokenError if the response code is not 200.
	 **/	
	public function updateAccessToken() {
		$body = array(
			'grant_type' => 'refresh_token',
			'client_id' => $this->clientId,
			'client_secret' => $this->clientSecret,
			'refresh_token' => $this->refreshToken
		);

		$headers = array(
			'Content-Type' => 'application/x-www-form-urlencoded',
			'user-agent'   => $this->userAgent
		);

		$urlEncodedBody = http_build_query( $body );
		$resp = _WPGSC_Http::postForm( TOKEN_URI, $urlEncodedBody, $headers );

		if ( $resp->code == 200 ) {
			$this->extractTokens( $resp->body );
			return $this;
		}
		else {
			$this->invalid = true;
			self::raiseFromJson( $resp );
		}
	}
	
	/**
	 * Revokes access via a refresh token.
	 *
	 * @param $refreshToken Token used to refresh access token.
	 * @return void
	 * @throws GSC_TokenError if the response code is not 200.
	 **/
	public function revoke( $refreshToken=null ) {
		if ($refreshToken == null) {
			$refreshToken = $this->refreshToken;
		}

		$query = array(
			'token' => $refreshToken
		);

		$uri = REVOKE_URI . '?' . http_build_query( $query );
		$resp = _WPGSC_Http::unsignedGet( $uri );

		if ( $resp->code == 200 ) {
			$this->invalid = true;
		}
		else {
			self::raiseFromJson( $resp );
		}
	}
	
    /**
     * Returns a token string from the object.
     *
     * @return string The authorization token string to be sent with a request.
     **/
    protected function getTokenString() {
        return 'Bearer ' . $this->accessToken;
    }
	
	/**
	 * Makes an authenticated request.
	 *
	 * @param $uri the uri to request
	 * @param $args the WP HTTP API arguments
	 * @return _GSC_Response The response to the request.
	 **/
	public function makeWPAuthenticatedRequest( $uri, $args ) {
		$headers = array(
			'Content-Type'  => 'application/atom+xml',
			'Authorization' => $this->getTokenString()
		);
		$args['headers'] = wp_parse_args( $headers, $args['headers'] );

		$result = wp_remote_request( $uri, $args );
		
		if( is_wp_error( $result ) )
			$result = _WPGSC_Http::wpErrorToResponse( $result );
		
		$resp = new _WPGSC_Response( $result );
		
		if( $resp->code == 401 ) {
			$this->refresh();
			
			$newHeaders = array(
				'Content-Type'  => 'application/x-www-form-urlencoded',
				'Authorization' => $this->getTokenString()
			);
			$args['headers'] = wp_parse_args( $newHeaders, $args['headers'] );
			
			$result = wp_remote_request( $uri, $args );
			
			if( is_wp_error( $result ) )
				$result = _WPGSC_Http::wpErrorToResponse( $result );
			
			return new _WPGSC_Response( $result );
		} else {
			return $resp;
		}
	}
}

/**
 * Client for making requests to the Google Content API for Shopping.
 * Extended to use WP flavours of Token classes and the WP HTTP API
 * most other code is replicated due to inheritance issues
 *
 * @package GShoppingContent
 * @version 1.3
 * @copyright Google Inc, 2012
 * @author afshar@google.com, dhermes@google.com, niall.campbell@gmail.com
 **/
class WPGSC_Client extends GSC_Client
{
    /**
     * Projection for the scope. Can be 'schema' (default) or 'generic'.
     *
     * @var string
     **
    public $projection = 'schema';
	 */	
	
    /**
     * Authorization token for the user.
     *
     * @var _GSC_Token
     **/
    private $token;
	
    /**
     * Create a new client for the merchant.
     *
     * @return GSC_Client The newliy created client.
     * @author afshar@google.com
     **
    public function __construct($merchantId)
    {
        $this->merchantId = $merchantId;
    }
	 */
	
    /**
     * Check that this client has been authorized and has a token.
     *
     * @throws GSC_ClientError if there is no token.
     * @return void
     */
    private function checkToken() {
        if ($this->token == null) {
            throw new GSC_ClientError('Client is not authenticated.');
        }
    }
	
    /**
     * Log in with ClientLogin and set the auth token.
     *
     * Included for backwards compatability purposes.
     *
     * @param string $email Google account email address.
     * @param string $password Google account password.
     * @return void
     **/
    public function login( $email, $password ) {
        $this->token = WPGSC_ClientLoginToken::login( $email, $password );
    }

    /**
     * Log in with ClientLogin and set the auth token.
     *
     * @param string $email Google account email address.
     * @param string $password Google account password.
     * @param string $userAgent The user agent. Describes application.
     * @return void
     **/
    public function clientLogin( $email, $password, $userAgent ) {
        $this->token = WPGSC_ClientLoginToken::login( $email, $password,
                                                   $userAgent );
    }

    /**
     * Set the token on the client with an unauthenticated OAuth2 token.
     *
     * @param string $clientId The client ID for the token.
     * @param string $clientSecret The client secret for the token.
     * @param string $redirectUri The redirect URI.
     * @param string $userAgent The user agent. Describes application.
     * @return void
     **/
    public function setOAuth2Token( $clientId, $clientSecret, $redirectUri, $userAgent ) {
        $this->token = new WPGSC_OAuth2Token( $clientId, $clientSecret,
                                           $redirectUri, $userAgent );
    }

    /**
     * Set the authentication token.
     *
     * @param _GSC_Token $token The authorization token.
     * @return void
     **/
    public function setToken( $token ) {
        $this->token = $token;
    }
	
    /**
     * Get all products.
	 * Modified to use _WPGSC_Http
     *
     * @param string $maxResults The max results desired. Defaults to null.
     * @param string $startToken The start token for the query. Defaults to null.
     * @param string $performanceStart The start date (inclusive) of click data
     *                                 returned. Should be represented as
     *                                 YYYY-MM-DD; not appended if left as None.
     * @param string $performanceEnd The end date (inclusive) of click data
     *                               returned. Should be represented as
     *                               YYYY-MM-DD; not appended if left as None.
     * @return GSC_ProductList parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getProducts( $maxResults=null, $startToken=null,
                                $performanceStart=null, $performanceEnd=null ) {
        $feedUri = $this->getFeedUri();

        $queryParams = array();
        if ( null != $maxResults ) {
            array_push( $queryParams, 'max-results=' . $maxResults );
        }
        if ( null != $startToken ) {
            array_push( $queryParams, 'start-token=' . $startToken );
        }
        if ( null != $performanceStart ) {
            array_push( $queryParams, 'performance.start=' . $performanceStart );
        }
        if ( null != $performanceEnd ) {
            array_push( $queryParams, 'performance.end=' . $performanceEnd );
        }

        if ( 0 < count( $queryParams ) ) {
            $feedUri .= '?' . join( '&', $queryParams );
        }

        $resp = _WPGSC_Http::get(
            $feedUri,
            $this->token
        );
        return _GSC_AtomParser::parse( $resp->body );
    }
	
    /**
     * Get a product from a link.
	 * Modified to use _WPGSC_Http
     *
     * @param string $link The edit link for the product.
     * @return GSC_Product parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getFromLink( $link ) {
        $resp = _WPGSC_Http::get(
            $link,
            $this->token
          );
        return _GSC_AtomParser::parse( $resp->body );
    }
	
    /**
     * Get a product.
     *
     * @param string $id The product id.
     * @param string $country The country specific to the product.
     * @param string $language The language specific to the product.
     * @return GSC_Product parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     *
    public function getProduct($id, $country, $language) {
        $link = $this->getProductUri($id, $country, $language, 'online');
        return $this->getFromLink($link);
    }
	 */
	 
    /**
     * Insert a product.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_Product $product The product to insert.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_Product parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function insertProduct( $product, $warnings=false, $dryRun=false ) {
        $feedUri = $this->appendQueryParams(
            $this->getFeedUri(),
            $warnings,
            $dryRun
        );

        $resp = _WPGSC_Http::post(
            $feedUri,
            $product->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parse( $resp->body );
    }
	
    /**
     * Update a product.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_Product $product The product to update.
     *                    Must have rel='edit' set.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_Product parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function updateProduct( $product, $warnings=false, $dryRun=false ) {
        $productUri = $this->appendQueryParams(
            $product->getEditLink(),
            $warnings,
            $dryRun
        );

        $resp = _WPGSC_Http::put(
            $productUri,
            $product->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parse( $resp->body );
    }
	

    /**
     * Send a delete request to a link.
	 * Modified to use _WPGSC_Http
     *
     * @param string $link The edit link for the product.
     * @throws GSC_ClientError if the response code is not 200.
     * @return void
     */
    public function deleteFromLink( $link ) {
        $resp = _WPGSC_Http::delete(
            $link,
            $this->token
          );

        if ($resp->code != 200) {
            throw new GSC_ClientError( 'Delete request failed:' . $resp->body . '.' );
        }
    }
	
    /**
     * Delete a product.
     *
     * @param GSC_Product $product The product to delete.
     *                    Must have rel='edit' set.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @throws GSC_ClientError if the response code is not 200.
     * @return void
     *
    public function deleteProduct($product, $warnings=false, $dryRun=false) {
        $productUri = $this->appendQueryParams(
            $product->getEditLink(),
            $warnings,
            $dryRun
        );

        $this->deleteFromLink($productUri);
    }
	*/

    /**
     * Make a batch request.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_ProductList $products The list of products to batch.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_ProductList The returned results from the batch.
     **/
    public function batch( $products, $warnings=false, $dryRun=false ) {
        $batchUri = $this->appendQueryParams(
            $this->getBatchUri(),
            $warnings,
            $dryRun
        );

        $resp = _WPGSC_Http::post(
            $batchUri,
            $products->toXML(),
            $this->token
        );
        return _GSC_AtomParser::parse( $resp->body );
    }

    /**
     * Create a feed object with a specified batch operation on each element.
     *
     * @param array $entries The list of entries to add in batch.
     * @param string $operation The batch operation desired.
     * @return GSC_ProductList|GSC_InventoryEntryList The constructed batch feed.
     *
    public function _createBatchFeed($entries, $operation, $feedType='product') {
        if ($feedType == 'inventory') {
          $entriesBatch = new GSC_InventoryEntryList();
        }
        else {
          // fallback for all unknown as well as 'product'
          $entriesBatch = new GSC_ProductList();
        }

        foreach ($entries as $entry) {
            $entry->setBatchOperation($operation);
            $entriesBatch->addEntry($entry);
        }

        return $entriesBatch;
    }
	*/

    /**
     * Insert a list of products.
     *
     * @param array $products The list of products to insert in batch.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_ProductList The returned results from the batch.
     *
    public function insertProducts($products, $warnings=false, $dryRun=false) {
        $productsBatch = $this->_createBatchFeed($products, 'insert');
        return $this->batch($productsBatch, $warnings, $dryRun);
    }
	*/	

    /**
     * Insert a list of products.
     *
     * @param array $products The list of products to insert in batch.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_ProductList The returned results from the batch.
     *

    public function insertProducts($products, $warnings=false, $dryRun=false) {
        $productsBatch = $this->_createBatchFeed($products, 'insert');
        return $this->batch($productsBatch, $warnings, $dryRun);
    }
	*/

    /**
     * Update a list of products.
     *
     * @param array $products The list of products to update in batch.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_ProductList The returned results from the batch.
     *
    public function updateProducts($products, $warnings=false, $dryRun=false) {
        $productsBatch = $this->_createBatchFeed($products, 'update');
        return $this->batch($productsBatch, $warnings, $dryRun);
    }
	*/

    /**
     * Delete a list of products.
     *
     * @param array $products The list of products to delete in batch.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return GSC_ProductList The returned results from the batch.
     *
    public function deleteProducts($products, $warnings=false, $dryRun=false) {
        $productsBatch = $this->_createBatchFeed($products, 'delete');
        return $this->batch($productsBatch, $warnings, $dryRun);
    }
	*/

    /**
     * Get all subaccounts.
	 * Modified to use _WPGSC_Http
     *
     * @param string $maxResults The max results desired. Defaults to null.
     * @param string $startIndex The start index for the query. Defaults to null.
     * @return GSC_ManagedAccountList parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getAccounts( $maxResults=null, $startIndex=null ) {
        $accountsUri = $this->getManagedAccountsUri();

        $queryParams = array();
        if ( null != $maxResults ) {
            array_push( $queryParams, 'max-results=' . $maxResults );
        }
        if ( null != $startIndex ) {
            array_push( $queryParams, 'start-index=' . $startIndex );
        }

        if ( 0 < count( $queryParams ) ) {
            $accountsUri .= '?' . join( '&', $queryParams );
        }

        $resp = _WPGSC_Http::get(
            $accountsUri,
            $this->token
        );
        return _GSC_AtomParser::parseManagedAccounts( $resp->body );
    }


    /**
     * Get a subaccount.
	 * Modified to use _WPGSC_Http
     *
     * @param string $accountId The account id.
     * @return GSC_ManagedAccount parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getAccount( $accountId ) {
        $resp = _WPGSC_Http::get(
            $this->getManagedAccountsUri( $accountId ),
            $this->token
          );
        return _GSC_AtomParser::parseManagedAccounts( $resp->body );
    }

    /**
     * Insert a subaccount.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_ManagedAccount $account The account to insert.
     * @return GSC_ManagedAccount The inserted account from the response.
     */
    public function insertAccount( $account ) {
        $resp = _WPGSC_Http::post(
            $this->getManagedAccountsUri(),
            $account->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseManagedAccounts( $resp->body );
    }

    /**
     * Update a subaccount.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_ManagedAccount $account The account to update.
     *                                    Must have rel='edit' set.
     * @return GSC_ManagedAccount parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function updateAccount( $account ) {
        $resp = _WPGSC_Http::put(
            $account->getEditLink(),
            $account->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseManagedAccounts( $resp->body );
    }

    /**
     * Delete a subaccount.
     *
     * @param GSC_ManagedAccount $account The account to delete.
     *                                    Must have rel='edit' set.
     * @throws GSC_ClientError if the response code is not 200.
     * @return void
     *
    public function deleteAccount($account) {
        $this->deleteFromLink($account->getEditLink());
    }
	*/

    /**
     * Get all datafeeds.
	 * Modified to use _WPGSC_Http
     *
     * @return GSC_DatafeedList parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getDatafeeds() {
        $resp = _WPGSC_Http::get(
            $this->getDatafeedsUri(),
            $this->token
        );
        return _GSC_AtomParser::parseDatafeeds( $resp->body );
    }

    /**
     * Get a datafeed.
	 * Modified to use _WPGSC_Http
     *
     * @param string $datafeedId The datafeed id.
     * @return GSC_Datafeed parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getDatafeed( $datafeedId ) {
        $resp = _WPGSC_Http::get(
            $this->getDatafeedsUri( $datafeedId ),
            $this->token
          );
        return _GSC_AtomParser::parseDatafeeds( $resp->body );
    }

    /**
     * Insert a datafeed.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_Datafeed $datafeed The datafeed to insert.
     * @return GSC_Datafeed The inserted datafeed from the response.
     */
    public function insertDatafeed( $datafeed ) {
        $resp = _WPGSC_Http::post(
            $this->getDatafeedsUri(),
            $datafeed->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseDatafeeds( $resp->body );
    }

    /**
     * Update a datafeed.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_Datafeed $datafeed The datafeed to update.
     *                               Must have rel='edit' set.
     * @return GSC_Datafeed parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function updateDatafeed( $datafeed ) {
        $resp = _WPGSC_Http::put(
            $datafeed->getEditLink(),
            $datafeed->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseDatafeeds( $resp->body );
    }

    /**
     * Delete a datafeed.
     *
     * @param GSC_Datafeed $datafeed The datafeed to delete.
     *                               Must have rel='edit' set.
     * @throws GSC_ClientError if the response code is not 200.
     * @return void
     *
    public function deleteDatafeed($datafeed) {
        $this->deleteFromLink($datafeed->getEditLink());
    }
	 */

    /**
     * Get all users.
	 * Modified to use _WPGSC_Http
     *
     * @return GSC_UserList parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getUsers() {
        $resp = _WPGSC_Http::get(
            $this->getUsersUri(),
            $this->token
        );
        return _GSC_AtomParser::parseUsers( $resp->body );
    }

    /**
     * Get a user.
	 * Modified to use _WPGSC_Http
     *
     * @param string $userEmail The email of a selected user.
     * @return GSC_User parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getUser( $userEmail ) {
        $resp = _WPGSC_Http::get(
            $this->getUsersUri( $userEmail ),
            $this->token
          );
        return _GSC_AtomParser::parseUsers( $resp->body );
    }

    /**
     * Insert a user.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_User $user The user to insert.
     * @return GSC_User The inserted user from the response.
     */
    public function insertUser( $user ) {
        $resp = _WPGSC_Http::post(
            $this->getUsersUri(),
            $user->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseUsers( $resp->body );
    }

    /**
     * Update a user.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_User $user The user to update.
     *                       Must have rel='edit' set.
     * @return GSC_User parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function updateUser( $user ) {
        $resp = _WPGSC_Http::put(
            $user->getEditLink(),
            $user->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseUsers( $resp->body );
    }

    /**
     * Delete a user.
     *
     * @param GSC_User $user The user to delete.
     *                       Must have rel='edit' set.
     * @throws GSC_ClientError if the response code is not 200.
     * @return void
     *
    public function deleteUser($user) {
        $this->deleteFromLink($user->getEditLink());
    }
	*/

    /**
     * Update an inventory entry.
	 * Modified to use _WPGSC_Http
     *
     * @param GSC_InventoryEntry $entry The inventory entry to update.
     *                                  Must have rel='edit' set.
     * @return GSC_InventoryEntry parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function updateInventoryEntry( $entry ) {
        $resp = _WPGSC_Http::put(
            $entry->getEditLink(),
            $entry->toXML(),
            $this->token
          );
        return _GSC_AtomParser::parseInventory( $resp->body );
    }

    /**
     * Update a list of inventory entries.
	 * Modified to use _WPGSC_Http
     *
     * Each entry must have rel='edit' set. To generate edit URI's for each product, first create
     * a feed URI specific to the store:
     * $storeBase = $client->getInventoryUri($storeId);
     * then for each individual product, create an product specific URI using the base:
     * $localProductUri = $client->getProductUri($id, $country, $language, 'local', $feedUri=$storeBase)
     *
     * Once you have a URI of this form, you can set it via:
     * $entry->setEditLink($localProductUri);
     *
     * @param array $entries The list of inventory entries to update in batch.
     * @return GSC_InventoryEntryList The returned results from the batch.
     **/
    public function updateInventoryFeed( $entries ) {
        $entriesBatch = $this->_createBatchFeed( $entries, 'update', 'inventory' );

        $resp = _WPGSC_Http::post(
            $this->getInventoryUri( null, true ),
            $entriesBatch->toXML(),
            $this->token
        );

        return _GSC_AtomParser::parseInventory( $resp->body );
    }


    /**
     * Get the data quality report for an individual account.
	 * Modified to use _WPGSC_Http
     *
     * @param array $secondaryAccountId The (optional) ID of a subaccount.
     *                                  If not specified, the merchant ID will
     *                                  be re-used.
     * @return GSC_DataQualityEntry parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getDataQualityEntry( $secondaryAccountId=null ) {
        if ( null == $secondaryAccountId ) {
          $secondaryAccountId = $this->merchantId;
        }
        $resp = _WPGSC_Http::get(
            $this->getDataQualityUri( $secondaryAccountId ),
            $this->token
        );
        return _GSC_AtomParser::parseDataQuality( $resp->body );
    }

    /**
     * Get the data quality feed.
	 * Modified to use _WPGSC_Http
     *
     * @param string $maxResults The max results desired. Defaults to null.
     * @param string $startIndex The start index for the query. Defaults to null.
     * @return GSC_DataQualityFeed parsed from the response.
     * @throws GSC_RequestError if the response is an errors element.
     */
    public function getDataQualityFeed( $maxResults=null, $startIndex=null ) {
        $dataQualityUri = $this->getDataQualityUri();

        $queryParams = array();
        if (null != $maxResults ) {
            array_push( $queryParams, 'max-results=' . $maxResults );
        }
        if (null != $startIndex ) {
            array_push( $queryParams, 'start-index=' . $startIndex );
        }

        if ( 0 < count( $queryParams ) ) {
            $dataQualityUri .= '?' . join( '&', $queryParams );
        }

        $resp = _WPGSC_Http::get(
            $dataQualityUri,
            $this->token
          );
        return _GSC_AtomParser::parseDataQuality( $resp->body );
    }

    /**
     * Create a URI for the feed for this merchant.
     *
     * @return string The feed URI.
     *
    public function getFeedUri() {
        return (BASE . $this->merchantId . '/items/products/' .
                $this->projection . '/');
    }
	 */

    /**
     * Create a URI for an individual product.
     *
     * @param string $id The product id.
     * @param string $country The country specific to the product.
     * @param string $language The language specific to the product.
     * @return string The product URI.
     *
    public function getProductUri($id, $country, $language, $channel, $feedUri=null) {
        if ($feedUri == null) {
          $feedUri = $this->getFeedUri();
        }
        return sprintf(
            '%s%s:%s:%s:%s',
            $feedUri,
            $channel,
            $language,
            $country,
            $id
        );
    }
	 */

    /**
     * Create a URI for the batch feed for this merchant.
     *
     * @return string The batch feed URI.
     *
    public function getBatchUri() {
        return $this->getFeedUri() . 'batch';
    }
	 */

    /**
     * Create a URI for the managed accounts feed for this merchant.
     *
     * @param string $accountId The account id. Defaults to null.
     * @return string The managedaccounts URI.
     *
    public function getManagedAccountsUri($accountId=null) {
        $result = BASE . $this->merchantId . '/managedaccounts';
        if ($accountId != null) {
            $result .= '/' . $accountId;
        }
        return $result;
    }
	 */

    /**
     * Create a URI for the datafeeds feed for this merchant.
     *
     * @param string $accountId The account id. Defaults to null.
     * @return string The datafeeds URI.
     *
    public function getDatafeedsUri($accountId=null) {
        $result = BASE . $this->merchantId . '/datafeeds/products';
        if ($accountId != null) {
            $result .= '/' . $accountId;
        }
        return $result;
    }
	 */

    /**
     * Create a URI for the users feed for this merchant.
     *
     * @param string $userEmail The email of a selected user. Defaults to null.
     * @return string The users URI.
     *
    public function getUsersUri($userEmail=null) {
        $result = BASE . $this->merchantId . '/users';

        if ($userEmail != null) {
            $result .= '/' . $userEmail;
        }
        return $result;
    }
	 */

    /**
     * Create a URI for the users feed for this merchant.
     *
     * @param string $userEmail The email of a selected user. Defaults to null.
     * @return string The users URI.
     *
    public function getInventoryUri($storeCode=null, $batch=false) {
        $result = BASE . $this->merchantId . '/inventory';

        if ($storeCode != null) {
            $result .= '/' . $storeCode . '/items/';
        }
        else if ($batch) {
            $result .= '/batch';
        }
        return $result;
    }
	 */

    /**
     * Create a URI for the data quality feed for this merchant.
     *
     * @param string $secondaryAccountId The (optional) ID of a subaccount.
     * @return string The data quality URI.
     *
    public function getDataQualityUri($secondaryAccountId=null) {
        $result = BASE . $this->merchantId . '/dataquality';

        if ($secondaryAccountId != null) {
            $result .= '/' . $secondaryAccountId;
        }
        return $result;
    }
	 */

    /**
     * Build a URI with warnings and dry-run query parameters.
     *
     * @param string $uri The URI to have parameters appended to.
     * @param boolean $warnings A boolean to determine if the warnings should be
     *                          included. Defaults to false.
     * @param boolean $dryRun A boolean to determine if the dry-run should be
     *                        included. Defaults to false.
     * @return string The URI with parameters included
     *
    public function appendQueryParams($uri, $warnings=false, $dryRun=false) {
        $queryParams = array();
        if ($warnings) {
            array_push($queryParams, 'warnings');
        }
        if ($dryRun) {
            array_push($queryParams, 'dry-run');
        }

        if (count($queryParams) > 0) {
            $uri .= '?' . join('&', $queryParams);
        }

        return $uri;
    }
	 */
}
?>