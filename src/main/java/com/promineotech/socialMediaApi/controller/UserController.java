package com.promineotech.socialMediaApi.controller;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.promineotech.socialMediaApi.entity.Credentials;
import com.promineotech.socialMediaApi.service.AuthenticationService;
import com.promineotech.socialMediaApi.service.UserService;

@RestController
@RequestMapping("/users")
public class UserController {
	
	private static String UPLOADED_FOLDER = "./pictures/";

	@Autowired
	private UserService service;
	
	@Autowired
	private AuthenticationService authService;
	
	//localhost:8080/users/register
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<Object> register(@RequestBody Credentials cred) {
		return new ResponseEntity<Object>(authService.register(cred, "USER"), HttpStatus.CREATED);
	}
	
	//localhost:8080/users/adminregister
		@RequestMapping(value = "/adminregister", method = RequestMethod.POST)
		public ResponseEntity<Object> adminRegister(@RequestBody Credentials cred, HttpServletRequest request) {
			try {
				if (authService.isAdmin(authService.getToken(request))) {
					return new ResponseEntity<Object>(authService.register(cred, "ADMIN"), HttpStatus.CREATED);
				} else {
					return new ResponseEntity<Object>("Unauthorized request", HttpStatus.UNAUTHORIZED);
				}
			} catch (Exception e) {
				return new ResponseEntity<Object>(e.getMessage(), HttpStatus.BAD_REQUEST);
			}
		}

	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public ResponseEntity<Object> login(@RequestBody Credentials cred) {
		try {
			return new ResponseEntity<Object>(authService.login(cred), HttpStatus.OK);
		} catch (Exception e) {
			return new ResponseEntity<Object>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "/{id}/follows")
	public ResponseEntity<Object> showFollowedUsers(@PathVariable Long id) {
		try {
			return new ResponseEntity<Object>(service.getFollowedUsers(id), HttpStatus.CREATED);
		} catch (Exception e) {
			return new ResponseEntity<Object>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}
	
	@RequestMapping(value = "/{id}/follows/{followId}", method = RequestMethod.POST)
	public ResponseEntity<Object> follow(@PathVariable Long id, @PathVariable Long followId) {
		try {
			return new ResponseEntity<Object>(service.follow(id, followId), HttpStatus.CREATED);
		} catch (Exception e) {
			return new ResponseEntity<Object>(e.getMessage(), HttpStatus.BAD_REQUEST);
		}
	}

	@RequestMapping(value="/{id}/profilePicture", method = RequestMethod.POST)
	public ResponseEntity<Object> singleFileUpload(@PathVariable Long id, @RequestParam("file") MultipartFile file) {
		if (file.isEmpty()) {
			return new ResponseEntity<Object>("Please upload a file.", HttpStatus.BAD_REQUEST);
		}

		try {
			String url = UPLOADED_FOLDER + file.getOriginalFilename();
			byte[] bytes = file.getBytes();
			Path path = Paths.get(url);
			Files.write(path, bytes);
			return new ResponseEntity<Object>(service.updateProfilePicture(id, url), HttpStatus.CREATED);
		} catch (Exception e) {
			return new ResponseEntity<Object>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
		} 
	}

}
