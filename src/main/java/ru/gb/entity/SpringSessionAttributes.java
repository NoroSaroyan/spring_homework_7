package ru.gb.entity;

import lombok.Data;

import javax.persistence.*;
import java.util.Collection;

@Entity
@Table(name = "SPRING_SESSION_ATTRIBUTES")
@Data
public class SpringSessionAttributes {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String SESSION_PRIMARY_ID;

    @Column(name = "ATTRIBUTE_NAME")
    private String ATTRIBUTE_NAME;

    @Column(name = "ATTRIBUTE_BYTES")
    private byte[] ATTRIBUTE_BYTES;

    @JoinTable(name = "SPRING_ATTRIBUTES_SESSION",
            joinColumns = @JoinColumn(name = "SESSION_PRIMARY_ID", referencedColumnName = "SESSION_PRIMARY_ID"),
            inverseJoinColumns = @JoinColumn(name = "SESSION_ID", referencedColumnName = "SESSION_ID")
    )

    @ManyToMany
    private Collection<SpringSession> springSessions;
}