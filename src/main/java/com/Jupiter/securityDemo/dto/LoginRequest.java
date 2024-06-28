package com.Jupiter.securityDemo.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

@Accessors(chain = true)
@Getter
@Setter
public class LoginRequest {
  private String username;
  private String password;

}
