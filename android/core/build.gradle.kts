import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.21"
}

group = "app.authenticator"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Argon2id for password-protected backups.
    implementation("org.bouncycastle:bcprov-jdk18on:1.81")
    // Provided by the Android platform at runtime.
    compileOnly("org.json:json:20250517")

    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20250517")
}

tasks.test {
    useJUnitPlatform()
    // Shared fixtures used by both the Windows and Android test suites.
    systemProperty("vectors.dir", rootDir.resolve("../../docs/test-vectors").absolutePath)
}
