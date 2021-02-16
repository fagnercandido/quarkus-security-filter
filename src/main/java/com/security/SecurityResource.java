package com.security;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.ApplicationScoped;
import javax.transaction.Transactional;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/security")
@ApplicationScoped
@Produces("application/json")
@Consumes("application/json")
public class SecurityResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("LINK")
    public String hello() {
        return "Hello RESTEasy";
    }


    @POST()
    @Produces(MediaType.TEXT_PLAIN)
    @PermitAll
    @Transactional
    public Response add(APIKey apiKey) {
        apiKey.persist();
        return Response.ok(apiKey).status(201).build();
    }
}