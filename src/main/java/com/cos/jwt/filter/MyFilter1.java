package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if(httpRequest.getMethod().equals("POST")) {
            String headerAuth = httpRequest.getHeader("Authorization");
            System.out.println(headerAuth);
            System.out.println("필터1");

            if(headerAuth.equals("cos"))
                chain.doFilter(httpRequest, httpResponse);
            else
                httpResponse.getWriter().println("인증 안됨");
        }
    }
}
