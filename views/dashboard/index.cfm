<div class="row pb-5 row-cols-lg-2 gx-4">
    <div class="col d-flex align-items-start">
        <div class="bg-light text-blue flex-shrink-0 me-3 px-2 fs-2 rounded-circle shadow-sm border border-3 border-white">
            <i class="bi bi-power"></i>
        </div>
        <div>
            <h2 class="text-blue">Current Users</h2>
            <cfscript>
                jwtService = jwtAuth();
                jwtUser = jwtService.isLoggedIn();

                authService = auth();
                userService = authService.getUserService();
                
                myUser = authService.authenticate('kevin@kinetic-interactive.com','cc123');

                
            </cfscript>
            <cfdump var="#myUser#">
        </div>
    </div>
</div>