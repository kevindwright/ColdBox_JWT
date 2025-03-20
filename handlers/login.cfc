component extends="coldbox.system.EventHandler" {

	/**
	 * Default Action
	 */
	function index( event, rc, prc ){

        authAttempt = auth().authenticate(rc.username,rc.password);

        return authAttempt;
	}


}
