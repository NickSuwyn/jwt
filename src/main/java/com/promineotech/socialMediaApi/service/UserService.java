package com.promineotech.socialMediaApi.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.promineotech.socialMediaApi.entity.User;
import com.promineotech.socialMediaApi.repository.UserRepository;
import com.promineotech.socialMediaApi.views.Following;

@Service
public class UserService {
	
	@Autowired
	private UserRepository repo;
	
	public Following follow(Long userId, Long followId) throws Exception {
		User user = repo.findOne(userId);
		User follow = repo.findOne(followId);
		if (user == null || follow == null) {
			throw new Exception("User does not exist.");
		}
		user.getFollowing().add(follow);
		repo.save(user);
		return new Following(user);
	}
	
	public Following getFollowedUsers(Long userId) throws Exception {
		User user = repo.findOne(userId);
		if (user == null) {
			throw new Exception("User does not exist.");
		}
		return new Following(user);
	}
	
	public User updateProfilePicture(Long userId, String url) throws Exception {
		User user = repo.findOne(userId);
		if (user == null) {
			throw new Exception("User does not exist.");
		}
		user.setProfilePictureUrl(url);
		return repo.save(user);
	}

}
