package id.adrena.api.oauth.model;

public class UserData {
	private String email;
	private String password;
	private int userId;
	private String userType;
	
	public UserData(String email, String password, int userId, String userType) {
		super();
		this.email = email;
		this.password = password;
		this.userId = userId;
		this.userType = userType;
	}
	public UserData() {
		super();
		// TODO Auto-generated constructor stub
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public int getUserId() {
		return userId;
	}
	public void setUserId(int userId) {
		this.userId = userId;
	}
	public String getUserType() {
		return userType;
	}
	public void setUserType(String userType) {
		this.userType = userType;
	}
	
	
}
