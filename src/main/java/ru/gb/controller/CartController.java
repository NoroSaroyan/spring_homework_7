package ru.gb.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import ru.gb.entity.Cart;
import ru.gb.entity.Product;
import ru.gb.repository.CartRepository;
import ru.gb.repository.ProductRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping(value = "/cart")
public class CartController {

    private final CartRepository repository;
    private final ProductRepository repositoryProduct;

    @Autowired
    public CartController(CartRepository repository, ProductRepository repositoryProduct) {
        this.repository = repository;
        this.repositoryProduct = repositoryProduct;
    }

    @GetMapping("/carts")
    public String findAll(@ModelAttribute("cartsList") List<Cart> carts, Model model) {

        carts = new ArrayList<>();
        repository.findAll().forEach(carts::add);
        model.addAttribute("cart", carts);
        return "/cart/carts";

    }

    @GetMapping("carts/{id}")
    public Optional<Cart> findById(@PathVariable Long id) {
        return repository.findById(id);
    }


    @DeleteMapping("/delete/{id}")
    public String delete(@PathVariable Long id) {
        repository.deleteById(id);
        return "redirect:/carts";
    }

    @PostMapping("/cartToAdd")
    public String cartToAdd(@PathVariable long countProduct, Product product,  BindingResult bindingResult, Model model) {

        if (bindingResult.hasErrors()) {
            return "/products/products";
        }
        repository.saveProductToCart(countProduct, product.getId());
        model.addAttribute("carts", new Cart());
        return "redirect:/carts";
    }


    @GetMapping("/cartToAdd")
    public String edit(Model model) {
        model.addAttribute("cart", new Cart());
        return "cart/cartToAdd";
    }
}
