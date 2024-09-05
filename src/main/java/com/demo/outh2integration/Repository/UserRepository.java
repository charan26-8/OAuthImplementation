package com.demo.outh2integration.Repository;

import com.demo.outh2integration.domain.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;


public interface UserRepository extends JpaRepository<User,Long> {
    Page<User> findAllByEmail(String auth, Pageable pageable);

    Optional<User>  findByEmail(String username);

    Page<User> findAllByEmailContainsAndEmail(String email, String auth, Pageable pageable);

    Page<User> findByEmailContains(String email, Pageable pageable);
}
