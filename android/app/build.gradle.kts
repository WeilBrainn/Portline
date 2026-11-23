plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }

android {
    namespace = "dev.portline.mobile"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.portline.mobile"
        minSdk = 26
        targetSdk = 35
        versionCode = 6
        versionName = "1.4.6"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("com.github.mwiede:jsch:0.2.21")
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
