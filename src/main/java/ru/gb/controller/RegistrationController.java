package ru.gb.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.gb.entity.User;
import ru.gb.repository.UserRepository;
import ru.gb.service.SecurityService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


@RequestMapping(value = "/auth")
@SessionAttributes("user")
public class RegistrationController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityService securityService;

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        request.getSession().invalidate();

        return "redirect:/login?logout";
    }

    @GetMapping("/registration")
    public String registration(Model model) {
        if (securityService.isAuthenticated()) {
            return "redirect:/";
        }

        model.addAttribute("user", new User());

        return "auth/registration";
    }

    @PostMapping("/registration")
    public String registration(@ModelAttribute("user") Model model, HttpServletRequest request, User userForm, BindingResult bindingResult) {

        HttpSession session = request.getSession();
        String email = request.getParameter("email");
        String password = request.getParameter("password");

        if (bindingResult.hasErrors()) {
            return "auth/registration";
        }
        if (email.equals(userForm.getEmail()) || password.equals(userForm.getPassword())) {
            model.addAttribute("error", "Your username and password is invalid.");
            return "auth/login";
        }
        userRepository.save(userForm);
        session.setAttribute(userForm.getEmail(), userForm);
        securityService.autoLogin(userForm.getEmail(), userForm.getPassword());

        return "redirect:/index";
    }

    @GetMapping("/login")
    public String login(Model model, String error, String logout, HttpSession session) {
        if (securityService.isAuthenticated()) {
            return "redirect:/index";
        }

        if (error != null)
            model.addAttribute("error", "Your username and password is invalid.");

        if (logout != null)
            model.addAttribute("message", "You have been logged out successfully.");

        return "auth/login";
    }

    @PostMapping("/login")
    public String userLogin(HttpServletRequest request, HttpServletResponse response, User userForm) {

        String email = request.getParameter("email");
        String password = request.getParameter("password");

        if (userForm.getEmail().equals(email) && userForm.getPassword().equals(password)) {
            securityService.autoLogin(userForm.getEmail(), userForm.getPassword());
            return "/index";
        }

        return "auth/login";
    }

    @GetMapping({"/", "/index"})
    public String welcome(Model model, HttpSession session) {
        return "/index";
    }

}
