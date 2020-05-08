package com.promineotech.socialMediaApi.views;

import com.promineotech.socialMediaApi.entity.User;

public class LoggedInView {
	
	private User user;
	private String jwt;
	
	public User getUser() {
		return user;
	}
	
	public void setUser(User user) {
		this.user = user;
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

}
