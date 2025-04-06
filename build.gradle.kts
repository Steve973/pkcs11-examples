plugins {
    java
    application
    alias(libs.plugins.lombok)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(libs.bouncycastle.fips)
    implementation(libs.bouncycastle.pkix.fips)
    implementation(libs.slf4j.simple)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.junit.platform.suite)
    testRuntimeOnly(libs.junit.platform.launcher)
}

allprojects {
    group = "com.example"
    version = "1.0.0-SNAPSHOT"
}

application {
    mainClass.set("com.example.pki.Pkcs11CertDemo")
}

tasks {
    test {
        useJUnitPlatform()
    }

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    compileJava {
        options.encoding = "UTF-8"
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }

    jar {
        manifest {
            attributes["Main-Class"] = "com.example.pki.Pkcs11CertDemo"
        }
    }
}
