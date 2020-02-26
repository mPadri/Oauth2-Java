package id.adrena.api.oauth.filter;

import java.io.IOException;
import java.text.ParseException;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import id.adrena.api.oauth.utils.JWKUtils;

public class Verifier {
	
	
	private static JWKSource<SecurityContext> getJWKS() throws IOException, ParseException{
		JWKSource<SecurityContext> key = new ImmutableJWKSet<SecurityContext>(JWKUtils.getSigningSet()); // mengambil jwks.json di satu project yang sama 
		return key;
	}
	
	private static JWSKeySelector<SecurityContext> getKey(JWSAlgorithm algorithm, JWKSource<SecurityContext> jwkSource){
		return new JWSVerificationKeySelector<>(algorithm, jwkSource);
	}
	public static JWTClaimsSet getJWTClaims(String token) throws IOException, ParseException, BadJOSEException, JOSEException {
		
		//verifikasi jwt (verifikasi struktur & signature jwt)
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
		jwtProcessor.setJWSKeySelector(getKey(JWSAlgorithm.RS256, getJWKS()));
		
		//ambil claim darei jwt
		JWTClaimsSet set = jwtProcessor.process(token, null);
		
		return set;
	}
}
