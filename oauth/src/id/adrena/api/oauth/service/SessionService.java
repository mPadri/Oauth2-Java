package id.adrena.api.oauth.service;

import java.time.Instant;
import java.util.Date;

import javax.ejb.Stateless;
import javax.ws.rs.core.Response;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import id.adrena.api.oauth.model.SessionRequest;
import id.adrena.api.oauth.model.SessionResult;
import id.adrena.api.oauth.model.Token;
import id.adrena.api.oauth.model.UserData;
import id.adrena.api.oauth.utils.JWKUtils;


@Stateless
public class SessionService {
	public UserData getUserDataFromDB() {
		return new UserData( "user@oauth.com", "HelloWorld@123", 1, "common" );
	}
	
		//----------------membuat akses token----------------------------------------------
		public SignedJWT generateAccessToken(String keyId, UserData user, int expireTime) {
			JWSHeader header = new JWSHeader
					.Builder(JWSAlgorithm.RS256)
					.keyID(keyId)
					.type(JOSEObjectType.JWT) //optional
					.build();
			
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.subject(String.valueOf(user.getUserId()))
					.claim("userType", user.getUserType())
					.issuer("localhost:8080")
					.issueTime(Date.from(Instant.now()))
					.expirationTime(Date.from(Instant.now().plusSeconds(expireTime)))
					.build();
			
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			
			
			RSASSASigner signer = null;
			
			try {
				
				JWK jwk = JWKUtils.getSigningSet().getKeyByKeyId(keyId);
				signer = new RSASSASigner(RSAKey.parse(jwk.toJSONObject()));
				signedJWT.sign(signer); //membuat signature
				
			} catch (Exception e) {
				e.printStackTrace();
			}
			return signedJWT;
		}
		
		//-----------------------------------------------------------------------------------
		
		//--------------------rfresh token---------------------------------------------------
		private JWEObject generateRefreshToken(String keyId,SignedJWT signedJWT) {
			 
			
			JWEHeader jweHeader = new JWEHeader
					.Builder(JWEAlgorithm.RSA_OAEP_256,EncryptionMethod.A256GCM)
					.contentType("JWT")
					.build();
			
			Payload payload = new Payload(signedJWT);
			JWEObject jweObject = new JWEObject(jweHeader, payload);
			
			try {
				JWK jwke = JWKUtils.getEncryptSet().getKeyByKeyId(keyId);
				RSAEncrypter encrypter = new RSAEncrypter(RSAKey.parse(jwke.toJSONObject()));
				jweObject.encrypt(encrypter);
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			return jweObject;
			
		}
		
		//----------------------------------------------------------------------------------
		
		public SessionResult verifyUser(SessionRequest request) {
			
			UserData user = getUserDataFromDB();
			
			if( !request.getUsername().equals(user.getEmail())
					|| !request.getPassword().equals(user.getPassword()) ) {
				return new SessionResult()
						.withHttpStatus(Response.Status.UNAUTHORIZED)
						.withErrorMessage("Username / password salah")
						.withResultSuccess(0);
			}
		
		Token token = new Token();
		token.setAccess(generateAccessToken("bebas", user, 3600)
				.serialize());
		token.setRefresh(generateRefreshToken("bebas-enc",generateAccessToken("bebas", user, 3600 * 24 *360))
				.serialize());
		token.setType("Bearer");
		token.setExpiresIn(3600);
		
		return new SessionResult()
				.withHttpStatus(Response.Status.OK)
				.withErrorMessage("")
				.withResultSuccess(1)
				.withToken(token);
		
		}
		
		
}
