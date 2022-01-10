package ru.gb.entity;

import lombok.Data;

import javax.persistence.*;
import java.util.Collection;

@Entity
@Table(name = "SPRING_SESSION")
@Data
public class SpringSession {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String PRIMARY_ID;

    @Column(name = "SESSION_ID")
    private String SESSION_ID;

    @Column(name = "CREATION_TIME")
    private long CREATION_TIME;

    @Column(name = "LAST_ACCESS_TIME")
    private long LAST_ACCESS_TIME;

    @Column(name = "MAX_INACTIVE_INTERVAL")
    private int MAX_INACTIVE_INTERVAL;

    @Column(name = "EXPIRY_TIME")
    private long EXPIRY_TIME;

    @Column(name = "PRINCIPAL_NAME")
    private String PRINCIPAL_NAME;

    @OneToMany
    private Collection<SpringSessionAttributes> springSessionAttributes;
}