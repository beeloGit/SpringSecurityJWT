package com.beels.springsecurity.restcontrollers;

import com.beels.springsecurity.models.AuthenticationRequest;
import com.beels.springsecurity.models.AuthenticationResponse;
import com.beels.springsecurity.services.MyUserDetailService;
import com.beels.springsecurity.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    @Autowired
    MyUserDetailService myUserDetailService;
    @Autowired
    JwtUtil jwtUtil;

    @Autowired
    AuthenticationManager authenticationManager;

    @RequestMapping(value = "/authenticate",method = RequestMethod.POST)
    public ResponseEntity<AuthenticationResponse> authenticateUser(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUserName(),
                    authenticationRequest.getPassword()));

        }catch (BadCredentialsException exception){
                throw  new Exception("Invalid username or password");
        }
        final UserDetails userDetails = myUserDetailService.loadUserByUsername(authenticationRequest.getUserName());
        String jwtToken = jwtUtil.createToken(userDetails);
        AuthenticationResponse authenticationResponse = new AuthenticationResponse(jwtToken);
        return  ResponseEntity.ok(authenticationResponse);





    }
    @RequestMapping("/login")
    public String login(){
        return "successufly logged in";
    }
}
