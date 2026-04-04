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
COPY ms-suppliers/src ./ms-suppliers/src
CMD ["sh", "-c", "mvn install -N -DskipTests && mvn install -pl shared -DskipTests && mvn spring-boot:run -pl ms-suppliers -Dspring-boot.run.profiles=dev"]

# Stage: builder
FROM base AS builder
COPY pom.xml .
COPY shared/pom.xml ./shared/
COPY ms-auth/pom.xml ./ms-auth/
COPY ms-contracts/pom.xml ./ms-contracts/
COPY ms-suppliers/pom.xml ./ms-suppliers/
RUN mvn dependency:go-offline -pl ms-suppliers -am || true
COPY shared/src ./shared/src
COPY ms-suppliers/src ./ms-suppliers/src
RUN mvn clean package -pl ms-suppliers -am -DskipTests

# Stage: staging
FROM eclipse-temurin:17-jre-alpine AS staging
WORKDIR /app
COPY --from=builder /app/ms-suppliers/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=staging
CMD ["java", "-jar", "app.jar"]

# Stage: production
FROM eclipse-temurin:17-jre-alpine AS production
WORKDIR /app
COPY --from=builder /app/ms-suppliers/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=prod
CMD ["java", "-jar", "app.jar"]
