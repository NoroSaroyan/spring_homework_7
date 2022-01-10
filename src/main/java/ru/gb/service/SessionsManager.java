package ru.gb.service;

import org.springframework.session.Session;

public interface SessionsManager<S extends Session> {

    S createSession();

    void save(S session);

    S findById(String id);

    void deleteById(String id);

    void deleteSessionExceptCurrentByUser(String username);
}
