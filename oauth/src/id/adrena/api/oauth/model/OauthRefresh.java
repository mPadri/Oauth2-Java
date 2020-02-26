package id.adrena.api.oauth.model;


public class OauthRefresh {
	
	private String refreshToken;

	public OauthRefresh(String refreshToken) {
		super();
		this.refreshToken = refreshToken;
	}

	public OauthRefresh() {
		super();
		// TODO Auto-generated constructor stub
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	
	
}
