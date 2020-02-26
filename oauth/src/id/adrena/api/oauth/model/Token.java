package id.adrena.api.oauth.model;

public class Token {
	private String access;
	private String refresh;
	private String type;
	private int expiresIn; // expired access token -> 3600s (1jam)
	
	public Token(String access, String refresh, String type, int expiresIn) {
		super();
		this.access = access;
		this.refresh = refresh;
		this.type = type;
		this.expiresIn = expiresIn;
	}
	public Token() {
		super();
		// TODO Auto-generated constructor stub
	}
	public String getAccess() {
		return access;
	}
	public void setAccess(String access) {
		this.access = access;
	}
	public String getRefresh() {
		return refresh;
	}
	public void setRefresh(String refresh) {
		this.refresh = refresh;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public int getExpiresIn() {
		return expiresIn;
	}
	public void setExpiresIn(int expiresIn) {
		this.expiresIn = expiresIn;
	}
	
}
