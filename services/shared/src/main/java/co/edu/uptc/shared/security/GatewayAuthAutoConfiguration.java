package co.edu.uptc.shared.security;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@EnableConfigurationProperties(GatewayAuthProperties.class)
@ConditionalOnProperty(
        prefix = "gateway",
        name   = "auth-filter.enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class GatewayAuthAutoConfiguration implements WebMvcConfigurer {

    // -- Filter ---------------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public GatewayAuthFilter gatewayAuthFilter(GatewayAuthProperties properties) {
        return new GatewayAuthFilter(properties);
    }

    @Bean
    public FilterRegistrationBean<GatewayAuthFilter> gatewayAuthFilterRegistration(
            GatewayAuthFilter filter) {

        FilterRegistrationBean<GatewayAuthFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setName("gatewayAuthFilter");
        return registration;
    }

    // -- Interceptor ----------------------------------------------------------

    @Bean
    @ConditionalOnMissingBean
    public ScopeInterceptor scopeInterceptor() {
        return new ScopeInterceptor();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(scopeInterceptor())
                .addPathPatterns("/**")
                .excludePathPatterns("/actuator/**");
    }
}