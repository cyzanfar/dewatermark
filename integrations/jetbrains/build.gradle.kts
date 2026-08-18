import org.jetbrains.intellij.platform.gradle.IntelliJPlatformType

plugins {
    java
    // The settings plugin supplies the implementation and version on the
    // buildscript classpath. Repeating the version here makes Gradle 9 reject
    // the plugin request because it cannot prove classpath compatibility.
    id("org.jetbrains.intellij.platform")
}

group = "com.cyzanfar.dewatermark"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform {
        defaultRepositories()
    }
}

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
    testRuntimeOnly("junit:junit:4.13.2")
    intellijPlatform {
        intellijIdea("2025.2.6.2")
        testFramework(org.jetbrains.intellij.platform.gradle.TestFrameworkType.Platform)
    }
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.release.set(21)
}

tasks.test {
    useJUnitPlatform()
}

intellijPlatform {
    pluginConfiguration {
        ideaVersion {
            sinceBuild = "252"
        }
    }
    pluginVerification {
        ides {
            // Keep compatibility evidence reproducible. The default
            // `recommended()` set floats as JetBrains publishes patches.
            create(IntelliJPlatformType.IntellijIdeaUltimate, "2025.2.6.3")
            create(IntelliJPlatformType.IntellijIdea, "2025.3.6.1")
            create(IntelliJPlatformType.IntellijIdea, "2026.1.5")
            create(IntelliJPlatformType.IntellijIdea, "2026.2.1")
        }
    }
}
