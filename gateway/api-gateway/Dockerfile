FROM maven:3.9.6-eclipse-temurin-17-alpine AS base
WORKDIR /app

# Stage: development
FROM base AS development
COPY pom.xml .
COPY src ./src
# Optionally map volume to /app
CMD ["mvn", "spring-boot:run", "-Dspring-boot.run.profiles=dev"]

# Stage: builder
FROM base AS builder
COPY pom.xml .
# Download dependencies first for better caching
RUN mvn dependency:go-offline || true
COPY src ./src
RUN mvn clean package -DskipTests

# Stage: staging
FROM eclipse-temurin:17-jre-alpine AS staging
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=staging
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]

# Stage: production
FROM eclipse-temurin:17-jre-alpine AS production
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
