package ru.kata.spring.boot_security.demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import ru.kata.spring.boot_security.demo.model.Role;
import ru.kata.spring.boot_security.demo.service.RoleService;
import ru.kata.spring.boot_security.demo.service.UserService;
import ru.kata.spring.boot_security.demo.model.User;
import java.security.Principal;
import java.util.List;
import ru.kata.spring.boot_security.demo.model.UserDto;

@Controller
public class UserController {

    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;

    // private Object Collection;

    @Autowired
    public UserController(UserService userService, RoleService roleService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
    }

    public record LoginRequest(String username, String password) {
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login"; // возвращаем имя представления для страницы входа
    }

    @GetMapping("/user")
    public String getHome(Model model, Principal principal) {
        if (principal != null) {
            model.addAttribute("user", userService.findByUsername(principal.getName()));
        }
        return "user-home";
    }
    // Logout с любой страницы
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/login?logout";
    }

//    @GetMapping("/admin")
//    public String findAll(Model model) {
//        List<User> users = userService.findAll();
//        model.addAttribute("users", users);
//
//        return "user-list";
//    }
    @GetMapping("/admin")
    public String findAll(Model model, Principal principal) {
        model.addAttribute("user", userService.findByUsername(principal.getName()));
        List<User> users = userService.findAll();
        List<Role> roles = roleService.getAllRoles();
        model.addAttribute("listRoles", roles); // Передаем список ролей в модель
        model.addAttribute("users", users);
        return "user-list";
    }

    @GetMapping("/admin/user-create")
    public String createUserForm(Model model) {
        List<Role> listRoles = roleService.getAllRoles();
        model.addAttribute("listRoles", listRoles);
        return "user-create";
    }

    @PostMapping("/admin")
    public String createUser(@RequestParam(name = "listRoles") List<Long> listRoles, User user) {
        List<Role> roles = roleService.findRolesByIds(listRoles);
        user.setRoles(roles);
        userService.saveUser(user);
        return "redirect:/admin";
    }

//    @GetMapping("admin/user-update/{id}")
//    public String updateUserForm(@PathVariable("id") Long id, Model model) {
//        User user = userService.findById(id);
//        model.addAttribute("user", user);
//        return "user-update";
//   }

    @GetMapping("admin/user-update/{id}")
    public String updateUserForm(@PathVariable("id") Long id, Model model) {
        User user = userService.findById(id);
        model.addAttribute("user", user);
        model.addAttribute("roles", roleService.getAllRoles());
        return "user-update";
    }

    @PostMapping("/admin/edit/{id}")
    public String updateUser(@PathVariable Long id, @RequestParam("listRoles") List<Long> listRoleIds, UserDto userDto) {
        // Логирование содержимого объекта UserDto
        System.out.println("Received UserDto: " + userDto);
        User existingUser = userService.findById(id);

        if (existingUser != null) {
            // Update other user details
            existingUser.setFirstName(userDto.getFirstName());
            existingUser.setLastName(userDto.getLastName());
            existingUser.setUsername(userDto.getUsername());

//            // Check if the password is changed
//            if (!userDto.getPassword().isEmpty()) {
//                // Password is changed, hash the new password
//                String encodedPassword = passwordEncoder.encode(userDto.getPassword());
//                existingUser.setPassword(encodedPassword);
//            }
            if (listRoleIds != null) {
                List<Role> roles = roleService.findRolesByIds(listRoleIds);
                existingUser.setRoles(roles);
            }
            userService.updateUser(existingUser); // Обновляем пользователя в базе данных

            return "redirect:/admin"; // Перенаправление на страницу деталей пользователя
        } else {
            return "redirect:/admin"; // Перенаправление на страницу списка пользователей
        }
    }

    @DeleteMapping("/admin/delete/{id}")
    public String deleteUser(@PathVariable("id") Long id) {
        userService.deleteById(id);
        return "redirect:/admin";
    }
}


