package ru.gb.controller;

import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.gb.entity.Category;
import ru.gb.repository.CategoryRepository;

import java.util.ArrayList;
import java.util.List;


@Controller
@RequestMapping("/category")
public class CategoryController {

    private final CategoryRepository repository;

    public CategoryController(CategoryRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/category-all")
    public String findAll(@ModelAttribute("categoriesList")  List<Category> categories, Model model) {

        categories =new ArrayList<>();
        repository.findAll().forEach(categories::add);
        return "category/category-all";
    }

    @GetMapping("/category-all/add")
    public String addForm(@ModelAttribute("categories") Model model) {

        model.addAttribute("categories", new Category());
        return "category/category-add";
    }

    @PostMapping
    public String add(@ModelAttribute("categories")
                      @RequestBody Category category) {
        repository.save(category);
        return "category/category-all";
    }
}
