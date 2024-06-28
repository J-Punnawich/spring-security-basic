package com.Jupiter.securityDemo.dto;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Accessors(chain = true)
@Getter
@Setter
@AllArgsConstructor
public class LoginResponse {

  private String jwtToken;
  private String username;
  private List<String> roles;

}
