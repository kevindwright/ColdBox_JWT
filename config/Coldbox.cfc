component {

	/**
	 * Configure the ColdBox App For Production
	 * https://coldbox.ortusbooks.com/getting-started/configuration
	 */
	function configure(){
		/**
		 * --------------------------------------------------------------------------
		 * ColdBox Directives
		 * --------------------------------------------------------------------------
		 * Here you can configure ColdBox for operation. Remember tha these directives below
		 * are for PRODUCTION. If you want different settings for other environments make sure
		 * you create the appropriate functions and define the environment in your .env or
		 * in the `environments` struct.
		 */
		coldbox = {
			// Application Setup
			appName                  : getSystemSetting( "MyAPI", "Simple API JWT Demo" ),
			eventName                : "event",
			// Development Settings
			reinitPassword           : "",
			reinitKey                : "fwreinit",
			handlersIndexAutoReload  : true,
			// Implicit Events
			defaultEvent             : "",
			requestStartHandler      : "Main.onRequestStart",
			requestEndHandler        : "",
			applicationStartHandler  : "Main.onAppInit",
			applicationEndHandler    : "",
			sessionStartHandler      : "",
			sessionEndHandler        : "",
			missingTemplateHandler   : "",
			// Extension Points
			applicationHelper        : "includes/helpers/ApplicationHelper.cfm",
			viewsHelper              : "",
			modulesExternalLocation  : [],
			viewsExternalLocation    : "",
			layoutsExternalLocation  : "",
			handlersExternalLocation : "",
			requestContextDecorator  : "",
			controllerDecorator      : "",
			// Error/Exception Handling
			invalidHTTPMethodHandler : "",
			exceptionHandler         : "main.onException",
			invalidEventHandler      : "",
			customErrorTemplate      : "/coldbox/system/exceptions/Whoops.cfm",
			// Application Aspects
			handlerCaching           : false,
			eventCaching             : false,
			viewCaching              : false,
			// Will automatically do a mapDirectory() on your `models` for you.
			autoMapModels            : true,
			// Auto converts a json body payload into the RC
			jsonPayloadToRC          : true
		};

		/**
		 * --------------------------------------------------------------------------
		 * Custom Settings
		 * --------------------------------------------------------------------------
		 */
		settings = {};

		/**
		 * --------------------------------------------------------------------------
		 * Environment Detection
		 * --------------------------------------------------------------------------
		 * By default we look in your `.env` file for an `environment` key, if not,
		 * then we look into this structure or if you have a function called `detectEnvironment()`
		 * If you use this setting, then each key is the name of the environment and the value is
		 * the regex patterns to match against cgi.http_host.
		 *
		 * Uncomment to use, but make sure your .env ENVIRONMENT key is also removed.
		 */
		// environments = { development : "localhost,^127\.0\.0\.1" };

		/**
		 * --------------------------------------------------------------------------
		 * Module Loading Directives
		 * --------------------------------------------------------------------------
		 */
		modules = {
			// An array of modules names to load, empty means all of them
			include : [],
			// An array of modules names to NOT load, empty means none
			exclude : []
		};

		/**
		 * --------------------------------------------------------------------------
		 * Application Logging (https://logbox.ortusbooks.com)
		 * --------------------------------------------------------------------------
		 * By Default we log to the console, but you can add many appenders or destinations to log to.
		 * You can also choose the logging level of the root logger, or even the actual appender.
		 */
		logBox = {
			// Define Appenders
			appenders : { coldboxTracer : { class : "coldbox.system.logging.appenders.ConsoleAppender" } },
			// Root Logger
			root      : { levelmax : "INFO", appenders : "*" },
			// Implicit Level Categories
			info      : [ "coldbox.system" ]
		};

		/**
		 * --------------------------------------------------------------------------
		 * Layout Settings
		 * --------------------------------------------------------------------------
		 */
		layoutSettings = { defaultLayout : "", defaultView : "" };

		/**
		 * --------------------------------------------------------------------------
		 * Custom Interception Points
		 * --------------------------------------------------------------------------
		 */
		interceptorSettings = { customInterceptionPoints : [] };

		/**
		 * --------------------------------------------------------------------------
		 * Application Interceptors
		 * --------------------------------------------------------------------------
		 * Remember that the order of declaration is the order they will be registered and fired
		 */
		interceptors = [];

		/**
		 * --------------------------------------------------------------------------
		 * Module Settings
		 * --------------------------------------------------------------------------
		 * Each module has it's own configuration structures, so make sure you follow
		 * the module's instructions on settings.
		 *
		 * Each key is the name of the module:
		 *
		 * myModule = {
		 *
		 * }
		 */
		moduleSettings = {

			cbauth = {
				// This is the path to your user object that contains the credential validation methods
				userServiceClass = "models.userService"
			},
		
			cbsecurity = {
				/**
				 * --------------------------------------------------------------------------
				 * Authentication Services
				 * --------------------------------------------------------------------------
				 * Here you will configure which service is in charge of providing authentication for your application.
				 * By default we leverage the cbauth module which expects you to connect it to a database via your own User Service.
				 *
				 * Available authentication providers:
				 * - cbauth : Leverages your own UserService that determines authentication and user retrieval
				 * - basicAuth : Leverages basic authentication and basic in-memory user registration in our configuration
				 * - custom : Any other service that adheres to our IAuthService interface
				 */
				authentication : {
					// The WireBox ID of the authentication service to use which must adhere to the cbsecurity.interfaces.IAuthService interface.
					"provider"        : "authenticationService@cbauth",
					// WireBox ID of the user service to use when leveraging user authentication, we default this to whatever is set
					// by cbauth or basic authentication. (Optional)
					"userService"     : "",
					// The name of the variable to use to store an authenticated user in prc scope on all incoming authenticated requests
					"prcUserVariable" : "oCurrentUser"
				},
		
				/**
				 * --------------------------------------------------------------------------
				 * Basic Auth
				 * --------------------------------------------------------------------------
				 * These settings are used so you can configure the hashing patterns of the user storage
				 * included with cbsecurity.  These are only used if you are using the `BasicAuthUserService` as
				 * your service of choice alongside the `BasicAuthValidator`
				 */
				basicAuth : {
					// Hashing algorithm to use
					hashAlgorithm  : "SHA-512",
					// Iterates the number of times the hash is computed to create a more computationally intensive hash.
					hashIterations : 5,
					// User storage: The `key` is the username. The value is the user credentials that can include
					// { roles: "", permissions : "", firstName : "", lastName : "", password : "" }
					users          : {}
				},
		
				/**
				 * --------------------------------------------------------------------------
				 * CSRF - Cross Site Request Forgery Settings
				 * --------------------------------------------------------------------------
				 * These settings configures the cbcsrf module. Look at the module configuration for more information
				 */
				csrf : {
					// By default we load up an interceptor that verifies all non-GET incoming requests against the token validations
					enableAutoVerifier     : false,
					// A list of events to exclude from csrf verification, regex allowed: e.g. stripe\..*
					verifyExcludes         : [],
					// By default, all csrf tokens have a life-span of 30 minutes. After 30 minutes, they expire and we aut-generate new ones.
					// If you do not want expiring tokens, then set this value to 0
					rotationTimeout        : 30,
					// Enable the /cbcsrf/generate endpoint to generate cbcsrf tokens for secured users.
					enableEndpoint         : false,
					// The WireBox mapping to use for the CacheStorage
					cacheStorage           : "CacheStorage@cbstorages",
					// Enable/Disable the cbAuth login/logout listener in order to rotate keys
					enableAuthTokenRotator : true
				},
				/**
				 * --------------------------------------------------------------------------
				 * Firewall Settings
				 * --------------------------------------------------------------------------
				 * The firewall is used to block/check access on incoming requests via security rules or via annotation on handler actions.
				 * Here you can configure the operation of the firewall and especially what Validator will be in charge of verifying authentication/authorization
				 * during a matched request.
				 */
				firewall : {
					// Auto load the global security firewall automatically, else you can load it a-la-carte via the `Security` interceptor
					"autoLoadFirewall"            : true,
					// The Global validator is an object that will validate the firewall rules and annotations and provide feedback on either authentication or authorization issues.
					"validator"                   : "AuthValidator@cbsecurity",
					// Activate handler/action based annotation security
					"handlerAnnotationSecurity"   : true,
					// The global invalid authentication event or URI or URL to go if an invalid authentication occurs
					"invalidAuthenticationEvent"  : "",
					// Default Auhtentication Action: override or redirect when a user has not logged in
					"defaultAuthenticationAction" : "redirect",
					// The global invalid authorization event or URI or URL to go if an invalid authorization occurs
					"invalidAuthorizationEvent"   : "",
					// Default Authorization Action: override or redirect when a user does not have enough permissions to access something
					"defaultAuthorizationAction"  : "redirect",
					// Firewall database event logs.
					"logs" : {
						"enabled"    : false,
						"dsn"        : "",
						"schema"     : "",
						"table"      : "cbsecurity_logs",
						"autoCreate" : true
					},
					// Firewall Rules, this can be a struct of detailed configuration
					// or a simple array of inline rules
					"rules"                       : {
						// Use regular expression matching on the rule match types
						"useRegex" : true,
						// Force SSL for all relocations
						"useSSL"   : false,
						// A collection of default name-value pairs to add to ALL rules
						// This way you can add global roles, permissions, redirects, etc
						"defaults" : {},
						// You can store all your rules in this inline array
						"inline"   : [],
						// If you don't store the rules inline, then you can use a provider to load the rules
						// The source can be a json file, an xml file, model, db
						// Each provider can have it's appropriate properties as well. Please see the documentation for each provider.
						"provider" : { "source" : "", "properties" : {} }
					}
				},
		
				/**
				 * --------------------------------------------------------------------------
				 * Security Visualizer
				 * --------------------------------------------------------------------------
				 * This is a debugging panel that when active, a developer can visualize security settings and more.
				 * You can use the `securityRule` to define what rule you want to use to secure the visualizer but make sure the `secured` flag is turned to true.
				 * You don't have to specify the `secureList` key, we will do that for you.
				 */
				visualizer : {
					"enabled"      : true,
					"secured"      : false,
					"securityRule" : {}
				},
		
				/**
				 * --------------------------------------------------------------------------
				 * Security Headers
				 * --------------------------------------------------------------------------
				 * This section is the way to configure cbsecurity for header detection, inspection and setting for common
				 * security exploits like XSS, ClickJacking, Host Spoofing, IP Spoofing, Non SSL usage, HSTS and much more.
				 */
				securityHeaders                     : {
					// Master switch for security headers
					"enabled" : true,
					// If you trust the upstream then we will check the upstream first for specific headers
					"trustUpstream"         : false,
					// Content Security Policy
					// Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks,
					// including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft, to
					// site defacement, to malware distribution.
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
					"contentSecurityPolicy" : {
						// Disabled by defautl as it is totally customizable
						"enabled" : false,
						// The custom policy to use, by default we don't include any
						"policy"  : ""
					},
					// The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in
					// the Content-Type headers should be followed and not be changed => X-Content-Type-Options: nosniff
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
					"contentTypeOptions" : { "enabled" : true },
					"customHeaders"      : {
						// Name : value pairs as you see fit.
					},
					// Disable Click jacking: X-Frame-Options: DENY OR SAMEORIGIN
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
					"frameOptions" : { "enabled" : true, "value" : "SAMEORIGIN" },
					// HTTP Strict Transport Security (HSTS)
					// The HTTP Strict-Transport-Security response header (often abbreviated as HSTS)
					// informs browsers that the site should only be accessed using HTTPS, and that any future attempts to access it
					// using HTTP should automatically be converted to HTTPS.
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security,
					"hsts"         : {
						"enabled"           : true,
						// The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS, 1 year is the default
						"max-age"           : "31536000",
						// See Preloading Strict Transport Security for details. Not part of the specification.
						"preload"           : false,
						// If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
						"includeSubDomains" : false
					},
					// Validates the host or x-forwarded-host to an allowed list of valid hosts
					"hostHeaderValidation" : {
						"enabled"      : false,
						// Allowed hosts list
						"allowedHosts" : ""
					},
					// Validates the ip address of the incoming request
					"ipValidation" : {
						"enabled"    : false,
						// Allowed IP list
						"allowedIPs" : ""
					},
					// The Referrer-Policy HTTP header controls how much referrer information (sent with the Referer header) should be included with requests.
					// Aside from the HTTP header, you can set this policy in HTML.
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
					"referrerPolicy"     : { "enabled" : true, "policy" : "same-origin" },
					// Detect if the incoming requests are NON-SSL and if enabled, redirect with SSL
					"secureSSLRedirects" : { "enabled" : false },
					// Some browsers have built in support for filtering out reflected XSS attacks. Not foolproof, but it assists in XSS protection.
					// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection,
					// X-XSS-Protection: 1; mode=block
					"xssProtection"      : { "enabled" : true, "mode" : "block" }
				},
		
				/**
				 * --------------------------------------------------------------------------
				 * Json Web Tokens Settings
				 * --------------------------------------------------------------------------
				 * Here you can configure the JWT services for operation and storage.  In order for your firewall
				 * to leverage JWT authentication/authorization you must make sure you use the `JwtAuthValidator` as your
				 * validator of choice; either globally or at the module level.
				 */
				jwt                          : {
					// The issuer authority for the tokens, placed in the `iss` claim
					"issuer"                  : "",
					// The jwt secret encoding key, defaults to getSystemEnv( "JWT_SECRET", "" )
					"secretKey"               : getSystemSetting( "JWT_SECRET", "" ),
					// by default it uses the authorization bearer header, but you can also pass a custom one as well.
					"customAuthHeader"        : "x-auth-token",
					// The expiration in minutes for the jwt tokens
					"expiration"              : 60,
					// If true, enables refresh tokens, longer lived tokens (not implemented yet)
					"enableRefreshTokens"     : false,
					// The default expiration for refresh tokens, defaults to 30 days
					"refreshExpiration"          : 10080,
					// The Custom header to inspect for refresh tokens
					"customRefreshHeader"        : "x-refresh-token",
					// If enabled, the JWT validator will inspect the request for refresh tokens and expired access tokens
					// It will then automatically refresh them for you and return them back as
					// response headers in the same request according to the customRefreshHeader and customAuthHeader
					"enableAutoRefreshValidator" : false,
					// Enable the POST > /cbsecurity/refreshtoken API endpoint
					"enableRefreshEndpoint"      : true,
					// encryption algorithm to use, valid algorithms are: HS256, HS384, and HS512
					"algorithm"               : "HS512",
					// Which claims neds to be present on the jwt token or `TokenInvalidException` upon verification and decoding
					"requiredClaims"          : [] ,
					// The token storage settings
					"tokenStorage"            : {
						// enable or not, default is true
						"enabled"       : true,
						// A cache key prefix to use when storing the tokens
						"keyPrefix"     : "cbjwt_",
						// The driver to use: db, cachebox or a WireBox ID
						"driver"        : "cachebox",
						// Driver specific properties
						"properties"    : {
							"cacheName" : "default"
						}
					}
				}
			}
		
		};

		/**
		 * --------------------------------------------------------------------------
		 * Flash Scope Settings
		 * --------------------------------------------------------------------------
		 * The available scopes are : session, client, cluster, ColdBoxCache, or a full instantiation CFC path
		 */
		flash = {
			scope        : "session",
			properties   : {}, // constructor properties for the flash scope implementation
			inflateToRC  : true, // automatically inflate flash data into the RC scope
			inflateToPRC : false, // automatically inflate flash data into the PRC scope
			autoPurge    : true, // automatically purge flash data for you
			autoSave     : true // automatically save flash scopes at end of a request and on relocations.
		};

		/**
		 * --------------------------------------------------------------------------
		 * App Conventions
		 * --------------------------------------------------------------------------
		 */
		conventions = {
			handlersLocation : "handlers",
			viewsLocation    : "views",
			layoutsLocation  : "layouts",
			modelsLocation   : "models",
			eventAction      : "index"
		};
	}

	/**
	 * Development environment
	 */
	function development(){
		// coldbox.customErrorTemplate = "/coldbox/system/exceptions/BugReport.cfm"; // static bug reports
		coldbox.customErrorTemplate = "/coldbox/system/exceptions/Whoops.cfm"; // interactive bug report
	}

}
