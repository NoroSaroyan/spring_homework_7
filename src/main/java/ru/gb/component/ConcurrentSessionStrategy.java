package ru.gb.component;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;
import ru.gb.service.SessionsManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
public class ConcurrentSessionStrategy extends ConcurrentSessionControlAuthenticationStrategy {
    private static final String FORCE_PARAMETER_NAME = "force";
    private final SessionsManager sessionsManager;

    public ConcurrentSessionStrategy(SessionRegistry sessionRegistry, SessionsManager sessionsManager) {
        super(sessionRegistry);
        this.sessionsManager = sessionsManager;
        super.setExceptionIfMaximumExceeded(true);
        super.setMaximumSessions(1);
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
                                 HttpServletResponse response)
            throws SessionAuthenticationException {
        try {
            super.onAuthentication(authentication, request, response);
        } catch (SessionAuthenticationException e) {
            log.debug("onAuthentication#SessionAuthenticationException");
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            String force = request.getParameter(FORCE_PARAMETER_NAME);

            if (!Boolean.parseBoolean(force)) {
                log.debug("onAuthentication#Invalidate current session for user: {}", userDetails.getUsername());
                throw e;
            }

            log.debug("onAuthentication#Invalidate old session for user: {}", userDetails.getUsername());
            sessionsManager.deleteSessionExceptCurrentByUser(userDetails.getUsername());

        }
    }
}