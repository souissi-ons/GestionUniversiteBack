FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copier d'abord pom.xml pour bénéficier du cache Docker
COPY pom.xml .

# Télécharger les dépendances (cette couche sera cachée si pom.xml ne change pas)
RUN mvn dependency:go-offline -B || true

# Copier le code source
COPY src ./src

# Build avec plusieurs tentatives en cas d'échec réseau
RUN mvn clean package -DskipTests -Dmaven.wagon.http.retryHandler.count=3

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8085
ENTRYPOINT ["java", "-jar", "app.jar"]