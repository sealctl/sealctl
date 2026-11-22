// Smoke test of the generated Kotlin bindings (SPEC 2.2, bindings.yml), run on the JVM with JNA:
// words B give the fingerprint and phone id of docs/vectors/v1.json, and open_request on the
// vector request gets through HPKE and the signature to the time check (the vector is old).
import uniffi.sealctl_core.*

fun value(json: String, key: String): String {
    val k = Regex.escape("\"$key\"")
    return Regex("$k\\s*:\\s*\"([^\"]*)\"").find(json)!!.groupValues[1]
}

fun main(args: Array<String>) {
    val json = java.io.File(args[0]).readText()
    val words = Words.parse(value(json, "B.mnemonic").split(" "))
    val root = Root.fromWords(words)
    check(fingerprint(root) == value(json, "B.fingerprint")) { "fingerprint" }
    val keys = PhoneKeys.fromRoot(root)
    check(keys.publicId() == value(json, "B.phone_identity_public_b64u")) { "phone id" }
    try {
        openRequest(keys, value(json, "machine.public_b64u"), value(json, "request.id"), value(json, "request.sealed"))
        error("an old vector request must be refused as expired")
    } catch (e: CoreException.Expired) {
        println("ok: fingerprint ${fingerprint(root)}, open_request reached the time check")
    }
}
