package ru.gb.entity;

import lombok.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Scope;


import javax.persistence.*;
import java.math.BigDecimal;
import java.util.List;

@Entity
@Table(name = "products")
@Data
@Scope("session")

public class Product extends ru.gb.web.service.Product {
    @Id
    @GeneratedValue
    @Column(name = "productId")
    long id;
    @Column(name = "productName")
    String name;
    @Column(name = "description")
    String description;
    @Column(name = "price")
    BigDecimal price;
    @ManyToMany
    List<Category> categories;
    @OneToMany
    List<Cart> carts;


    public Product(@Value("id") long id,
                   @Value("name") String name,
                   @Value( "description") String description,
                   @Value("price")  BigDecimal price){
        this.id=id;
        this.name = name;
        this.description = description;
        this.price = price;

    }

    public Product() {

    }
}