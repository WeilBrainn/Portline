plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "dev.portline.mobile"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.portline.mobile"
        minSdk = 26
        targetSdk = 35
        versionCode = 12
        versionName = "1.4.12"
    }
    signingConfigs {
        getByName("debug") {
            storeFile = file(System.getenv("PORTLINE_KEYSTORE_PATH") ?: "../debug.keystore")
            storePassword = System.getenv("PORTLINE_KEYSTORE_PASSWORD") ?: "android"
            keyAlias = System.getenv("PORTLINE_KEY_ALIAS") ?: "androiddebugkey"
            keyPassword = System.getenv("PORTLINE_KEY_PASSWORD") ?: "android"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources {
            excludes += setOf("META-INF/versions/*/OSGI-INF/MANIFEST.MF", "META-INF/DEPENDENCIES", "META-INF/LICENSE*", "META-INF/NOTICE*")
        }
    }
}

dependencies {
    implementation("com.github.mwiede:jsch:0.2.21")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bctls-jdk18on:1.79")
}

val syncPortlineAssets by tasks.registering(Copy::class) {
    val assetsDir = layout.projectDirectory.dir("src/main/assets")
    into(assetsDir)
    from(layout.projectDirectory.dir("../../ui")) { into("ui") }
    from(layout.projectDirectory.dir("../../scripts")) { into("scripts") }
    from(layout.projectDirectory.file("../../bin/portline-gateway-linux-amd64")) { into("bin") }
}

tasks.named("preBuild") {
    dependsOn(syncPortlineAssets)
}
