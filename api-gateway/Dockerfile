FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

COPY pom.xml .

RUN mvn dependency:go-offline -B || true

COPY src ./src

RUN mvn clean package -DskipTests -Dmaven.wagon.http.retryHandler.count=3

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8888
ENTRYPOINT ["java", "-jar", "app.jar"]