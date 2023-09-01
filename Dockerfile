FROM maven:3.8.7-openjdk-18 as builder

COPY src /usr/src/app/src
COPY pom.xml /usr/src/app

RUN mvn -f /usr/src/app/pom.xml clean package

FROM quay.io/keycloak/keycloak:22.0.1


COPY --from=builder /usr/src/app/target/keycloak-events-0.20-SNAPSHOT.jar /opt/keycloak/providers/


RUN /opt/keycloak/bin/kc.sh build


