package id.adrena.api.oauth.endpoint;

import java.io.IOException;
import java.text.ParseException;

import javax.ejb.EJB;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import id.adrena.api.oauth.model.OauthRefresh;
import id.adrena.api.oauth.model.SessionResult;
import id.adrena.api.oauth.model.Token;
import id.adrena.api.oauth.service.SessionService;
import id.adrena.api.oauth.utils.JWKUtils;

@Path("refresh")
public class OauthEndpoint {
	
	@EJB
	private SessionService service;
	
	private JWTClaimsSet verifyRefreshToken(String refreshToken) throws IOException, ParseException, BadJOSEException, JOSEException {
		
		//----membuka enkrip lapis pertama rferes token----------------------------------------------------
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		
		JWEAlgorithm exJweAlgorithm = JWEAlgorithm.RSA_OAEP_256; //algoritma untuk refers token kita 
		EncryptionMethod exEncryptionMethod = EncryptionMethod.A256GCM; // metode enkripsi yang dipakai refersh token kita
		
		//jwk set yang dipakai untuk enkrip refersh token kita
		JWKSource<SecurityContext> jwkSource = 
				new ImmutableJWKSet<>(JWKUtils.getEncryptSet());
		
		JWEKeySelector<SecurityContext> jweKeySelector = 
				new JWEDecryptionKeySelector<>(exJweAlgorithm, exEncryptionMethod, jwkSource);
		
		jwtProcessor.setJWEKeySelector(jweKeySelector);
		//--------------------------------------------------------------------------------------
		
		//-------------membuka lapis kedua enksripsi rfres token---------------------------------------------
		
		//algoritma yang dipakai utk signature access token kita 
		JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
		
		//jwk set yang dipakai untuk signature access token kita 
		JWKSource<SecurityContext> jwskeysource = 
				new ImmutableJWKSet<>(JWKUtils.getSigningSet());
		
		JWSKeySelector<SecurityContext> keyselector = 
				new JWSVerificationKeySelector<>(expectedJWSAlg, jwskeysource);
		
		jwtProcessor.setJWSKeySelector(keyselector);
		
		//---------------------------------------------------------------------------------------
		
		//-----------------melakukan verifikasi token----------------------------------------------------
		
		DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = 
				new DefaultJWTClaimsVerifier<SecurityContext>();
		jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
		
		return jwtProcessor.process(refreshToken, null);
		
		//----------------------------------------------------------------------------------------------
		
	}
	
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response postRefreshToken(OauthRefresh request) {
		
		//------------memberikan akses token yang baru-----------------------------------------------
		SessionResult result = null;
		
		try {
			JWTClaimsSet refresClaim = verifyRefreshToken(request.getRefreshToken());
			
			if(refresClaim.getStringClaim("userType").equals("common")) {
				Token token = new Token();
				token.setAccess(service.generateAccessToken("bebas", service.getUserDataFromDB(), 3600).serialize());
				token.setExpiresIn(3600);
				token.setType("Bearer");
				
				result = new SessionResult()
						.withHttpStatus(Response.Status.OK)
						.withResultSuccess(1)
						.withErrorMessage("")
						.withToken(token);
				
			}else {
				result = new SessionResult()
						.withHttpStatus(Response.Status.BAD_REQUEST)
						.withResultSuccess(0)
						.withErrorMessage("invalid refresh token");
			}
		} catch (Exception e) {
			e.printStackTrace();
			
			result = new SessionResult()
					.withHttpStatus(Response.Status.INTERNAL_SERVER_ERROR)
					.withResultSuccess(0)
					.withErrorMessage("internal server erorr");

		}
		
		return Response
				.status(result.getHttpStatus())
				.entity(result)
				.build();
		
	}
	
}
