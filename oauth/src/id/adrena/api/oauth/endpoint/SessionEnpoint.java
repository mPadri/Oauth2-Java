package id.adrena.api.oauth.endpoint;

import javax.ejb.EJB;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import id.adrena.api.oauth.model.SessionRequest;
import id.adrena.api.oauth.model.SessionResult;
import id.adrena.api.oauth.service.SessionService;

@Path("session")
public class SessionEnpoint {

	@EJB
	private SessionService service;
	
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response postSession(SessionRequest request) {
		
		SessionResult result = service.verifyUser(request);
		
		return Response
				.status(result.getHttpStatus())
				.entity(result)
				.build();
	}
}
