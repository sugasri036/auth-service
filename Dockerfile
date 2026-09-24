# =====================================================
# 1. BUILD STAGE
# =====================================================

FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /app

# Copy Maven configuration first
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw .

RUN chmod +x mvnw

# Download dependencies first
RUN ./mvnw dependency:go-offline

# Copy source code
COPY src src

# Build application
RUN ./mvnw clean package -DskipTests


# =====================================================
# 2. RUNTIME STAGE
# =====================================================

FROM eclipse-temurin:21-jre

WORKDIR /app


# =====================================================
# NON-ROOT USER
# =====================================================

RUN groupadd --system spring \
    && useradd --system \
       --gid spring \
       --home-dir /app \
       --shell /usr/sbin/nologin \
       spring


# =====================================================
# COPY JAR
# =====================================================

COPY --from=build \
    /app/target/*.jar \
    app.jar


# =====================================================
# APPLICATION PORT
# =====================================================

EXPOSE 10000


# =====================================================
# RUN AS NON-ROOT
# =====================================================

USER spring


# =====================================================
# JVM CONTAINER SETTINGS
# =====================================================

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]