package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository라는 @Annotation이 없어도 IoC 됨
// JpaRepostiory를 상속받았기 때문
public interface UserRepository extends JpaRepository<User, Integer> {

    // findBy 규칙 -> Username 문법
    // select * from user where username = ?
    public User findByUsername(String username);

}
