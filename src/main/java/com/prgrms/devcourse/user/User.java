package com.prgrms.devcourse.user;

import jakarta.persistence.*;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Table(name = "users")
public class User {

  @Id
  @Column(name = "id")
  private Long id;

  @Column(name = "login_id")
  private String loginId;

  @Column(name = "passwd")
  private String passwd;

  @ManyToOne(optional = false)
  @JoinColumn(name = "group_id")
  private Group group;

  public void checkPassword(PasswordEncoder passwordEncoder, String credentials) {
    if (!passwordEncoder.matches(credentials, passwd))
      throw new IllegalArgumentException("Bad credential");
  }

  public Long getId() {
    return id;
  }

  public String getLoginId() {
    return loginId;
  }

  public String getPasswd() {
    return passwd;
  }

  public Group getGroup() {
    return group;
  }

  @Override
  public String toString() {
    return "User{" +
            "id=" + id +
            ", loginId='" + loginId + '\'' +
            ", passwd='" + passwd + '\'' +
            ", group=" + group +
            '}';
  }
}