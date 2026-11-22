// Smoke test of the generated Swift bindings (SPEC 2.2, bindings.yml): words B give the
// fingerprint and phone id of docs/vectors/v1.json, and open_request on the vector request
// gets through HPKE and the signature to the time check (the vector is old: Expired).
import Foundation

let path = CommandLine.arguments[1]
let data = try Data(contentsOf: URL(fileURLWithPath: path))
let v = try JSONSerialization.jsonObject(with: data) as! [String: Any]
func s(_ k: String) -> String { v[k] as! String }

let words = try Words.parse(list: s("B.mnemonic").split(separator: " ").map(String.init))
let root = Root.fromWords(words: words)
precondition(fingerprint(root: root) == s("B.fingerprint"), "fingerprint")
let keys = PhoneKeys.fromRoot(root: root)
precondition(keys.publicId() == s("B.phone_identity_public_b64u"), "phone id")
do {
    _ = try openRequest(keys: keys, relayMachineKey: s("machine.public_b64u"), id: s("request.id"), sealed: s("request.sealed"))
    preconditionFailure("an old vector request must be refused as expired")
} catch CoreError.Expired {
    print("ok: fingerprint \(fingerprint(root: root)), open_request reached the time check")
}
