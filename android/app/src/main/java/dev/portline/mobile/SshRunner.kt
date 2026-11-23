package dev.portline.mobile

import com.jcraft.jsch.ChannelExec
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.nio.charset.StandardCharsets

object SshRunner {
    private val ansiRegex = Regex("\\x1B\\[[0-?]*[ -/]*[@-~]")

    fun runScript(
        host: String,
        port: Int,
        username: String,
        authType: String,
        password: String,
        keyContentOrPath: String,
        script: String,
        timeoutMs: Int = 180_000,
        onLine: (String) -> Unit
    ) {
        val jsch = JSch()
        var session: Session? = null
        var channel: ChannelExec? = null
        try {
            if (authType == "key" && keyContentOrPath.isNotBlank()) {
                val trimmed = keyContentOrPath.trim()
                if (trimmed.contains("BEGIN ")) {
                    jsch.addIdentity("portline-key", trimmed.toByteArray(StandardCharsets.UTF_8), null, null)
                } else {
                    jsch.addIdentity(trimmed)
                }
            }
            session = jsch.getSession(username, host, port).apply {
                if (authType == "password") {
                    setPassword(password)
                }
                setConfig("StrictHostKeyChecking", "no")
                setConfig("PreferredAuthentications", if (authType == "key") "publickey" else "password,keyboard-interactive")
                connect(20_000)
            }
            val cmd = if (username == "root") "bash -s" else "sudo -n bash -s"
            channel = (session.openChannel("exec") as ChannelExec).apply {
                setCommand(cmd)
            }
            val errStream = channel.errStream
            val outStream = channel.inputStream
            val inPipe = PipedOutputStream()
            channel.setInputStream(PipedInputStream(inPipe, 65536))
            channel.connect(15_000)

            val writerThread = Thread({
                try {
                    inPipe.write(script.toByteArray(StandardCharsets.UTF_8))
                    inPipe.flush()
                    inPipe.close()
                } catch (_: Exception) {
                }
            }, "PortlineSshWrite").apply { start() }

            val errLines = mutableListOf<String>()
            val errThread = Thread({
                try {
                    BufferedReader(InputStreamReader(errStream, StandardCharsets.UTF_8)).useLines { lines ->
                        lines.forEach { raw ->
                            val clean = raw.replace(ansiRegex, "").trim()
                            if (clean.isNotEmpty()) {
                                synchronized(errLines) { errLines.add(clean) }
                                onLine(clean)
                            }
                        }
                    }
                } catch (_: Exception) {
                }
            }, "PortlineSshErr").apply { start() }

            BufferedReader(InputStreamReader(outStream, StandardCharsets.UTF_8)).useLines { lines ->
                lines.forEach { raw ->
                    val clean = raw.replace(ansiRegex, "").trim()
                    if (clean.isNotEmpty()) {
                        onLine(clean)
                    }
                }
            }

            writerThread.join(5_000)
            errThread.join(5_000)

            val deadline = System.currentTimeMillis() + timeoutMs
            while (!channel.isClosed && System.currentTimeMillis() < deadline) {
                Thread.sleep(100)
            }
            val exitStatus = channel.exitStatus
            if (exitStatus != 0) {
                val tail = synchronized(errLines) { errLines.takeLast(3).joinToString(" | ") }
                throw IllegalStateException(
                    if (tail.isNotEmpty()) "SSH exit $exitStatus: $tail" else "SSH exit $exitStatus"
                )
            }
        } finally {
            try { channel?.disconnect() } catch (_: Exception) {}
            try { session?.disconnect() } catch (_: Exception) {}
        }
    }
}
