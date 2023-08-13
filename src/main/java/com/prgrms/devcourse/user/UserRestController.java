package com.prgrms.devcourse.user;

import com.prgrms.devcourse.jwt.JwtAuthentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class UserRestController {

  private final UserService userService;

  public UserRestController(UserService userService) {
    this.userService = userService;
  }

  /**
   * 보호받는 엔드포인트 - ROLE_USER 또는 ROLE_ADMIN 권한 필요함
   */
  @GetMapping(path = "/user/me")
  public UserDto me(@AuthenticationPrincipal JwtAuthentication authentication) {
    return userService.findByUsername(authentication.username)
            .map(user ->
                    new UserDto(authentication.token, authentication.username, user.getGroup().getName())
            )
            .orElseThrow(() -> new IllegalArgumentException("Could not found user for " + authentication.username));
  }

}