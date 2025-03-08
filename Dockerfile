FROM openjdk:17-jdk-alpine AS builder

WORKDIR /app/spring-boot-jwt

COPY ./pom.xml /app
COPY ./.mvn ./.mvn
COPY ./mvnw .
COPY ./pom.xml .

RUN ./mvnw dependency:go-offline

COPY ./src ./src

RUN ./mvnw clean package -DskipTests

FROM openjdk:17-jdk-alpine

WORKDIR /app
RUN mkdir ./logs

COPY --from=builder /app/spring-boot-jwt/target/spring-boot-jwt-0.0.1-SNAPSHOT.jar .
EXPOSE 8080

CMD ["java", "-jar", "spring-boot-jwt-0.0.1-SNAPSHOT.jar"]