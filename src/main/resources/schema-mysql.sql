CREATE TABLE SPRING_SESSION (
                                PRIMARY_ID CHAR(36) NOT NULL,
                                SESSION_ID CHAR(36) NOT NULL,
                                CREATION_TIME BIGINT NOT NULL,
                                LAST_ACCESS_TIME BIGINT NOT NULL,
                                MAX_INACTIVE_INTERVAL INT NOT NULL,
                                EXPIRY_TIME BIGINT NOT NULL,
                                PRINCIPAL_NAME VARCHAR(100),
                                CONSTRAINT SPRING_SESSION_PK PRIMARY KEY (PRIMARY_ID)
);


CREATE UNIQUE INDEX SPRING_SESSION_IX1 ON SPRING_SESSION (SESSION_ID);
CREATE INDEX SPRING_SESSION_IX2 ON SPRING_SESSION (EXPIRY_TIME);
CREATE INDEX SPRING_SESSION_IX3 ON SPRING_SESSION (PRINCIPAL_NAME);

CREATE TABLE SPRING_SESSION_ATTRIBUTES (
                                           SESSION_PRIMARY_ID CHAR(36) NOT NULL,
                                           ATTRIBUTE_NAME VARCHAR(200) NOT NULL,
                                           ATTRIBUTE_BYTES LONGVARBINARY NOT NULL,
                                           CONSTRAINT SPRING_SESSION_ATTRIBUTES_PK PRIMARY KEY (SESSION_PRIMARY_ID, ATTRIBUTE_NAME),
                                           CONSTRAINT SPRING_SESSION_ATTRIBUTES_FK FOREIGN KEY (SESSION_PRIMARY_ID) REFERENCES SPRING_SESSION(PRIMARY_ID) ON DELETE CASCADE
);

CREATE INDEX SPRING_SESSION_ATTRIBUTES_IX1 ON SPRING_SESSION_ATTRIBUTES (SESSION_PRIMARY_ID);


create table if not exists PRODUCTS
(
    ID BIGINT auto_increment primary key,
    NAME VARCHAR (255),
    description VARCHAR (255),
    price decimal

);

create table if not exists USERS
(
    ID BIGINT auto_increment primary key,
    login VARCHAR (50) not null,
    password VARCHAR (50) not null,
    authority VARCHAR (50) not null
);



create table if not exists categories
(
    ID BIGINT auto_increment primary key,
    name VARCHAR (255)

);

create table if not exists products_categories
(
    productID BIGINT,
    categoryID BIGINT,
    constraint TABLE_PRODUCKS_ID_FK foreign key
        (productID) references PRODUCTS (ID),
    constraint TABLE_categorys_ID_FK foreign key
        (categoryID) references categories (ID )

);

create table if not exists order
(
    ID BIGINT auto_increment primary key,
    order_carried  BOOLEAN

);

create table if not exists order_order_product
(
    orderID BIGINT,
    order_productID BIGINT,
    constraint TABLE_ORDER_ID_FK foreign key
(orderID) references ORDER (ID),
    constraint TABLE_ORDER_PRODUCT_ID_FK foreign key
(order_productID) references order_product (ID )

);

create table if not exists order_product
(
    ID BIGINT auto_increment primary key,
    countProduct BIGINT,
    productID BIGINT,
    constraint TABLE_PRODUCTS_ID_FK foreign key
        (productID) references PRODUCTS (ID)

);


