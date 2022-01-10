package ru.gb.web.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ws.server.endpoint.annotation.Endpoint;

import org.springframework.ws.server.endpoint.annotation.PayloadRoot;
import org.springframework.ws.server.endpoint.annotation.RequestPayload;
import org.springframework.ws.server.endpoint.annotation.ResponsePayload;
import ru.gb.repository.CategoryRepository;
import ru.gb.repository.ProductRepository;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;


@Endpoint
public class InfoResourceEndpoint {

    private final ProductRepository productService;
    private final CategoryRepository categoryRepository;
    private static final String NAMESPACE_URL = "http:/gb.ru/web.service";

    @Autowired
    public InfoResourceEndpoint(ProductRepository productService, CategoryRepository categoryRepository) {
        this.productService = productService;
        this.categoryRepository = categoryRepository;
    }

    @PayloadRoot(namespace = NAMESPACE_URL, localPart = "getProductRequest")
    @ResponsePayload
    public GetProductResponse getProductResponse(@RequestPayload GetProductRequest request) {
        GetProductResponse response = new GetProductResponse();
        response.setProduct(productService.getById(request.getId()));
        return response;
    }

    @PayloadRoot(namespace = NAMESPACE_URL, localPart = "getListProductResponse")
    @ResponsePayload
    public  List<GetListProductResponse> listProduct (@RequestPayload GetListProductRequest request){

        GetListProductResponse response = new GetListProductResponse();
        List<GetListProductResponse> responses = new ArrayList<>() ;
        List<Product>productList = new ArrayList<>();
        productService.findAll().forEach(productList::add);
        for (int i = 0; i < productList.size(); i++) {
            response.setProduct(productList.get(i));
            if(response.getProduct().category.categoryName.equals(request.name)) {
                responses.add(response);
            }
        }
        return responses;
    }

}


