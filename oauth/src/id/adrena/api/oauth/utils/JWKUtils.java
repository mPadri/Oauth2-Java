package id.adrena.api.oauth.utils;

import java.io.IOException;
import java.text.ParseException;

import com.nimbusds.jose.jwk.JWKSet;

public class JWKUtils {
	/**
	 * fungsi throws IOException, ParseException agar jika error yang menghandel dari enpoint */
	
	public static JWKSet getSigningSet() throws IOException, ParseException {
		return JWKSet.load(JWKUtils.class.getResourceAsStream("/jwk/jwks.json"));
	}
	
	public static JWKSet getEncryptSet() throws IOException, ParseException {
		return JWKSet.load(JWKUtils.class.getResourceAsStream("/jwk/jwks-enc.json"));
	}
}
