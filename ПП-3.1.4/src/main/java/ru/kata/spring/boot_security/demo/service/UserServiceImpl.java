package ru.kata.spring.boot_security.demo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.model.User;
import ru.kata.spring.boot_security.demo.repository.UserRepository;
import ru.kata.spring.boot_security.demo.repository.RoleRepository;

import javax.transaction.Transactional;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


@Service
public class UserServiceImpl implements UserService {
//public class UserServiceImpl implements UserService, Serializable {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder; // Внедряем PasswordEncoder

    private String username;

    //  @Autowired
    public UserServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    @Override
    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Transactional
    @Override
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Transactional
    @Override
    public void deleteById(Long id) {
        userRepository.deleteById(id);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }


//    @Override
//    public User findByUsername(String name) throws UsernameNotFoundException{
//        return userRepository.findByUsername(name).orElse(null );
//    }

//    @Transactional
//    @Override
//    public User findByUsername(String username) {
//        this.username = username;
//        return userRepository.findByUsername(username);
//    }

    @Transactional
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("User '%s' not found", username));
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(), user.getPassword(), roles(user.getRoles())
        );
    }

    @Transactional
    @Override
    public void editUser(User user, List<Role> roles) {
        user.setRoles(roles);
        updateUser(user);
    }

    @Override
    @Transactional
    public void updateUser(User user) {
        user.setId(user.getId());
        userRepository.save(user);
    }


    //    @Override
//    @Transactional
//    public void updateUser(User user) {
//        User existingUser = userRepository.findById(user.getId()).orElse(null);
//        if (existingUser != null) {
//            // Check if a new password is provided
//            if (user.getPassword() != null && !user.getPassword().isEmpty()) {
//                // Password is provided, hash the new password
//                String encodedPassword = passwordEncoder.encode(user.getPassword());
//                existingUser.setPassword(encodedPassword);
//            }
//            // Update other user details
//            existingUser.setFirstName(user.getFirstName());
//            existingUser.setLastName(user.getLastName());
//            existingUser.setUsername(user.getUsername());
//
//            // Save the updated user
//            userRepository.save(existingUser);
//        }
//    }
    @Transactional
    @Override
    public void saveUser(User user) {
        // Хеширование пароля перед сохранением
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userRepository.save(user);
    }

    @Transactional
    public User get(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    @Transactional
    public Collection<? extends GrantedAuthority> roles(Collection<Role> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }
}


