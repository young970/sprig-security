package com.prgrms.devcourse.user;

import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

import static java.util.stream.Collectors.toList;

@Entity
@Table(name = "groups")
public class Group {

  @Id
  @Column(name = "id")
  private Long id;

  @Column(name = "name")
  private String name;

  @OneToMany(mappedBy = "group")
  private List<GroupPermission> permissions = new ArrayList<>();

  public Long getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public List<GrantedAuthority> getAuthorities() {
    return permissions.stream()
      .map(gp -> new SimpleGrantedAuthority(gp.getPermission().getName()))
      .collect(toList());
  }

  @Override
  public String toString() {
    return "Group{" +
            "id=" + id +
            ", name='" + name + '\'' +
            ", permissions=" + permissions +
            '}';
  }
}