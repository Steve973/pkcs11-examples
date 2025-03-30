plugins {
    java
    application
}

group = "com.example"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bc-fips:2.1.0")
    implementation("org.bouncycastle:bcpkix-fips:2.1.9")
    implementation("org.slf4j:slf4j-simple:2.0.17")
    
    compileOnly("org.projectlombok:lombok:1.18.30")
    annotationProcessor("org.projectlombok:lombok:1.18.30")
    
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
}

application {
    mainClass.set("com.example.pki.Pkcs11CertDemo")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    sourceCompatibility = "17"
    targetCompatibility = "17"
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = "com.example.pki.Pkcs11CertDemo"
    }
}