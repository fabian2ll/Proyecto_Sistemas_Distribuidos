FROM maven:3.9.6-eclipse-temurin-17-alpine AS base
WORKDIR /app

# Stage: development
FROM base AS development
COPY pom.xml .
COPY shared/pom.xml ./shared/
COPY ms-auth/pom.xml ./ms-auth/
COPY ms-contracts/pom.xml ./ms-contracts/
COPY ms-suppliers/pom.xml ./ms-suppliers/
COPY shared/src ./shared/src
COPY ms-auth/src ./ms-auth/src
# In dev we run specific module
CMD ["sh", "-c", "mvn install -N -DskipTests && mvn install -pl shared -DskipTests && mvn spring-boot:run -pl ms-auth -Dspring-boot.run.profiles=dev"]

# Stage: builder
FROM base AS builder
COPY pom.xml .
COPY shared/pom.xml ./shared/
COPY ms-auth/pom.xml ./ms-auth/
COPY ms-contracts/pom.xml ./ms-contracts/
COPY ms-suppliers/pom.xml ./ms-suppliers/
RUN mvn dependency:go-offline -pl ms-auth -am || true
COPY shared/src ./shared/src
COPY ms-auth/src ./ms-auth/src
RUN mvn clean package -pl ms-auth -am -DskipTests

# Stage: staging
FROM eclipse-temurin:17-jre-alpine AS staging
WORKDIR /app
COPY --from=builder /app/ms-auth/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=staging
CMD ["java", "-jar", "app.jar"]

# Stage: production
FROM eclipse-temurin:17-jre-alpine AS production
WORKDIR /app
COPY --from=builder /app/ms-auth/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=prod
CMD ["java", "-jar", "app.jar"]
