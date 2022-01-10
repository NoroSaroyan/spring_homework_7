package ru.gb.exception;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;

import org.springframework.stereotype.Component;

import java.sql.SQLException;


@Aspect
@Component
public class ExceptionHandlerAspect extends PointCutConfig {

    @AfterThrowing(pointcut = "publicMethodInsideCartControllerDoLogg()", throwing = "e")
    public void cartControllerThrowing (JoinPoint joinPoint, Exception e) throws Throwable {
        Class cla = joinPoint.getSignature().getDeclaringType();
        Logger logger = LogManager.getLogger(cla);
        logger.error("Exception occured in " + cla, e);
        System.out.println("Exception occured in " + cla + e);
        handel(joinPoint, e);
    }

    @AfterThrowing(pointcut = "publicMethodInsideProductControllerDoLogg()", throwing = "e")
    public void productControllerThrowing (JoinPoint joinPoint, Exception e) throws Throwable {
        Class cla = joinPoint.getSignature().getDeclaringType();
        Logger logger = LogManager.getLogger(cla);
        logger.error("Exception occured in " + cla, e);
        System.out.println("Exception occured in " + cla + e);
        handel(joinPoint, e);
    }
    @AfterThrowing(pointcut = "publicMethodInsideCategoryControllerDoLogg()", throwing = "e")
    public void categoryControllerThrowing (JoinPoint joinPoint, Exception e) throws Throwable {
        Class cla = joinPoint.getSignature().getDeclaringType();
        Logger logger = LogManager.getLogger(cla);
        logger.error("Exception occured in " + cla, e);
        System.out.println("Exception occured in " + cla + e);
        handel(joinPoint, e);
    }
    @AfterThrowing(pointcut = "publicMethodInsideRegistrationControllerDoLogg()", throwing = "e")
    public void registrationControllerThrowing (JoinPoint joinPoint, Exception e) throws Throwable {
        Class cla = joinPoint.getSignature().getDeclaringType();
        Logger logger = LogManager.getLogger(cla);
        logger.error("Exception occured in " + cla, e);
        System.out.println("Exception occured in " + cla + e);
        handel(joinPoint, e);
    }
    private void handel(JoinPoint joinPoint, Exception e) throws Throwable {
        DAOException dae = null;
        Throwable throwable = e;
        while (throwable != null && !(throwable instanceof SQLException)) {
            throwable = throwable.getCause();
        }
        if (throwable instanceof SQLException) {
            dae = new DAOException("SERVICE_ERROR_IN_DB_PROCESS", e.getMessage(),
                    (SQLException) throwable);
        }
        if (dae != null) {
            throw dae;
        } else {
            throw e;
        }
    }
}