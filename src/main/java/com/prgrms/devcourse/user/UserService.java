package com.prgrms.devcourse.user;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkArgument;
import static io.micrometer.common.util.StringUtils.isNotEmpty;

@Service
public class UserService {

  private final PasswordEncoder passwordEncoder;

  private final UserRepository userRepository;

  public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
    this.passwordEncoder = passwordEncoder;
    this.userRepository = userRepository;
  }

  @Transactional(readOnly = true)
  public User login(String principal, String credentials) {
    checkArgument(isNotEmpty(principal), "principal must be provided.");
    checkArgument(isNotEmpty(credentials), "credentials must be provided.");

    User user = userRepository.findByLoginId(principal)
            .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + principal));
    user.checkPassword(passwordEncoder, credentials);
    return user;
  }

  @Transactional(readOnly = true)
  public Optional<User> findByLoginId(String loginId) {
    checkArgument(isNotEmpty(loginId), "loginId must be provided.");
    return  userRepository.findByLoginId(loginId);
  }


//  @Override
//  @Transactional(readOnly = true)
//  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//    return userRepository.findByLoginId(username)
//      .map(user ->
//        User.builder()
//          .username(user.getLoginId())
//          .password(user.getPasswd())
//          .authorities(user.getGroup().getAuthorities())
//          .build()
//      )
//      .orElseThrow(() -> new UsernameNotFoundException("Could not found user for " + username));
//
//  }

}