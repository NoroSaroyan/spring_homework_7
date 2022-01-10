package ru.gb.entity;


import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import javax.persistence.*;


@Entity
@Table(name = "categories")
@Data
@Component
@Scope("session")
public class Category {
    @Id
    @GeneratedValue
    @Column(name = "categoryId")
    private long id;
    @Column(name = "categoryName")
    private String name;

    public Category(@Value("categoryId") long id,
                    @Value("categoryName") String name) {
        this.id = id;
        this.name = name;

    }

    public Category() {

    }
}