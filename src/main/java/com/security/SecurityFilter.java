package com.security;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import org.jboss.resteasy.core.Headers;
import org.jboss.resteasy.core.ResourceMethodInvoker;
import org.jboss.resteasy.core.ServerResponse;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.*;

@Provider
public class SecurityFilter implements ContainerRequestFilter {

    private static final String AUTHORIZATION_PROPERTY = "API_KEY";
    private static final ServerResponse ACCESS_DENIED = new ServerResponse("Access denied for this resource", 401, new Headers<Object>());
    private static final ServerResponse ACCESS_FORBIDDEN = new ServerResponse("Nobody can access this resource", 403, new Headers<Object>());
    private static final ServerResponse SERVER_ERROR = new ServerResponse("INTERNAL SERVER ERROR", 500, new Headers<Object>());


    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        ResourceMethodInvoker methodInvoker = (ResourceMethodInvoker) containerRequestContext.getProperty("org.jboss.resteasy.core.ResourceMethodInvoker");
        Method method = methodInvoker.getMethod();

        if (!method.isAnnotationPresent(PermitAll.class)) {
            if (method.isAnnotationPresent(DenyAll.class)) {
                containerRequestContext.abortWith(ACCESS_FORBIDDEN);
                return;
            }
            final MultivaluedMap<String, String> headers = containerRequestContext.getHeaders();
            final List<String> apiKeyHeader = headers.get(AUTHORIZATION_PROPERTY);

            if (Objects.isNull(apiKeyHeader) || apiKeyHeader.isEmpty()) {
                containerRequestContext.abortWith(ACCESS_DENIED);
                return;
            }

            final String apiKey = apiKeyHeader.stream().findFirst().orElse(null);
            if (method.isAnnotationPresent(RolesAllowed.class)) {
                RolesAllowed rolesAnnotation = method.getAnnotation(RolesAllowed.class);
                Set<String> rolesSet = new HashSet<String>(Arrays.asList(rolesAnnotation.value()));
                if (!isUserAllowed(apiKey, rolesSet)) {
                    containerRequestContext.abortWith(ACCESS_DENIED);
                }
            }
        }
    }

    private boolean isUserAllowed(String apiKeyHeader, final Set<String> rolesSet) {
        List<APIKey> listApiKey = APIKey.find("apiKey", apiKeyHeader).list();
        Optional<APIKey> first = listApiKey.stream().findFirst();
        return first.filter(apiKey -> rolesSet.contains(apiKey.role)).isPresent();
    }
}
