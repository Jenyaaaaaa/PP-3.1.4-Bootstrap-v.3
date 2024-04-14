//package ru.kata.spring.boot_security.demo.configs;
//
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.web.context.request.RequestContextHolder;
//import org.springframework.web.context.request.ServletRequestAttributes;
//
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import javax.servlet.http.HttpSession;
//
//import static org.springframework.web.util.WebUtils.getSessionId;
//
//public class CustomBCryptPasswordEncoder extends BCryptPasswordEncoder {
//
//    // Конструктор класса, принимающий HttpServletRequest
//    private final HttpServletRequest request;
//
//    public CustomBCryptPasswordEncoder(HttpServletRequest request) {
//        this.request = request;
//    }
//
//    private static final ThreadLocal<HttpServletRequest> requestHolder = new ThreadLocal<>();
//
//    public static void setRequest(HttpServletRequest request) {
//        requestHolder.set(request);
//    }
//
//    public static void removeRequest() {
//        requestHolder.remove();
//    }
//
//    private static HttpServletRequest getRequest() {
//        return requestHolder.get();
//    }
//
//   //@Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
//        // Получение введённого пользователем пароля из запроса
//        String rawPassword = request.getParameter("password");
//
//        // Получение закодированного пароля из базы данных для пользователя Petr
//        String encodedPasswordFromDatabase = "$2a$10$d6p/GowCBMypgtOsL4X9dupNVzQQy.ammZwt3uYXJmWEJbnxuN/KO";
//
//        // Создание экземпляра BCryptPasswordEncoder
//        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
//
//        // Проверка совпадения введённого пользователем пароля с закодированным паролем из базы данных
//        if (passwordEncoder.matches(rawPassword, encodedPasswordFromDatabase)) {
//            // Если пароли совпадают, то аутентификация успешна
//            // Создаем объект Authentication для аутентифицированного пользователя
//            Authentication authentication = new UsernamePasswordAuthenticationToken("Petr", "$2a$10$d6p/GowCBMypgtOsL4X9dupNVzQQy.ammZwt3uYXJmWEJbnxuN/KO");
//            // Возвращаем аутентификационный объект
//            return authentication;
//        } else {
//            // Если пароли не совпадают, выбрасываем исключение AuthenticationException
//            throw new BadCredentialsException("Пароли не совпадают. Аутентификация не удалась.");
//        }
//    }
//
//
//
//    @Override
//    public boolean matches(CharSequence rawPassword, String encodedPassword) {
//        // Получаем HttpServletRequest из ThreadLocal
//        HttpServletRequest request = getRequest();
//        // Логируем переданный пароль и хешированный пароль из базы данных
//        System.out.println("Matching password for user:");
//        System.out.println("Raw password: " + rawPassword);
//        System.out.println("Encoded password from database: " + encodedPassword);
//
//        // Вывод информации о пользователе
//        System.out.println("Username: " + getUsername());
//
//        // Вывод контекста вызова
//        System.out.println("Request URL: " + getRequestUrl());
//        System.out.println("Session ID: " + getSessionId());
//
//        // Вызываем метод суперкласса для проверки пароля
//        boolean matches = super.matches(rawPassword, encodedPassword);
//
//        // Логирование результата аутентификации
//        if (matches) {
//            System.out.println("Authentication successful!");
//        } else {
//            System.out.println("Authentication failed!");
//        }
//
//        return super.matches(rawPassword, encodedPassword);
//    }
//
//    private String getUsername() {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
//            return ((UserDetails) authentication.getPrincipal()).getUsername();
//        } else {
//            return "anonymousUser";
//        }
//    }
//
//
//    // Метод для получения URL запроса
//    private String getRequestUrl() {
//        return request.getRequestURI();
//    }
//
//    // Метод для получения идентификатора сессии
//    private String getSessionId() {
//        HttpSession session = request.getSession(false);
//        return (session != null) ? session.getId() : "Session not found";
//    }
//
//}






// Метод для получения имени пользователя из контекста Spring Security
//    private String getUsername() {
//        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//        if (principal instanceof UserDetails) {
//            return ((UserDetails) principal).getUsername();
//        } else {
//            return principal.toString();
//        }
//    }