package ru.gb.exception;

import org.aspectj.lang.annotation.Pointcut;

public class PointCutConfig {
	@Pointcut("within(ru.gb.controller.CartController.*)")
	protected void cartControllerDoLogg() {
	}

	@Pointcut("within(ru.gb.controller.ProductController.*)")
	protected void productControllerDoLogg() {
	}

	@Pointcut("within(ru.gb.controller.CategoryController.*)")
	protected void categoryControllerDoLogg() {
	}

	@Pointcut("within(ru.gb.controller.RegistrationController.*)")
	protected void registrationControllerDoLogg() {
	}

	@Pointcut("execution(public * *(..))")
	protected void publicMethod() {
	}

	@Pointcut("publicMethod() && cartControllerDoLogg()")
	protected void publicMethodInsideCartControllerDoLogg() {
	}

	@Pointcut("publicMethod() && productControllerDoLogg()")
	protected void publicMethodInsideProductControllerDoLogg() {
	}

	@Pointcut("publicMethod() && categoryControllerDoLogg()")
	protected void publicMethodInsideCategoryControllerDoLogg() {
	}

	@Pointcut("publicMethod() && registrationControllerDoLogg()")
	protected void publicMethodInsideRegistrationControllerDoLogg() {
	}

}