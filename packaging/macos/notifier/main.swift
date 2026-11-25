// sealctl Notifier: shows sealctl's desktop notifications on macOS under the name "sealctl"
// with the sealctl icon (SPEC 5.2). The daemon runs it with names only, never values:
//
//   sealctl-notifier --id <id> --title <title> --body <body> [--replace]
//   sealctl-notifier --id <id> --remove
//
// --replace updates a notification already shown with the same id, without a sound.
//
// Exit codes: 0 shown (or removed), 2 bad arguments, 3 notifications are not allowed for sealctl,
// 4 macOS asked the user whether to allow them and the answer came late (or never), 5 any other
// failure. The daemon waits a few seconds for the exit code and shows the notification another
// way (osascript) when it is not 0 or does not come.

import Foundation
import UserNotifications

let usage = "usage: sealctl-notifier --id <id> (--title <t> --body <b> [--replace] | --remove)"

var id: String?
var title: String?
var body: String?
var replace = false
var remove = false

var args = CommandLine.arguments.dropFirst().makeIterator()
while let a = args.next() {
    switch a {
    case "--id": id = args.next()
    case "--title": title = args.next()
    case "--body": body = args.next()
    case "--replace": replace = true
    case "--remove": remove = true
    default:
        // Launched with no arguments (a click on a notification opens the app): nothing to do.
        // macOS may add its own arguments (-psn_…); ignore them.
        if a.hasPrefix("-psn_") { continue }
        FileHandle.standardError.write("\(usage)\n".data(using: .utf8)!)
        exit(2)
    }
}
guard let id, !id.isEmpty else {
    if CommandLine.arguments.count <= 1 { exit(0) }
    FileHandle.standardError.write("\(usage)\n".data(using: .utf8)!)
    exit(2)
}

let center = UNUserNotificationCenter.current()

/// Runs `body` and waits up to `seconds` for it to call its completion.
func wait(_ seconds: Double, _ body: (@escaping () -> Void) -> Void) -> Bool {
    let done = DispatchSemaphore(value: 0)
    body { done.signal() }
    return done.wait(timeout: .now() + seconds) == .success
}

/// Settles pending requests: the center answers in order, so once this answers, earlier calls
/// reached it and the process may exit.
func settle() {
    _ = wait(2) { finish in center.getDeliveredNotifications { _ in finish() } }
}

if remove {
    center.removeDeliveredNotifications(withIdentifiers: [id])
    center.removePendingNotificationRequests(withIdentifiers: [id])
    settle()
    exit(0)
}

guard let title, let body else {
    FileHandle.standardError.write("\(usage)\n".data(using: .utf8)!)
    exit(2)
}

// Allowed? The first time, macOS asks the user with a notification of its own ("sealctl" would
// like to send you notifications: Allow). The prompt goes away when this process exits, so it
// waits for the answer, up to 10 minutes. The answer is kept for the bundle id: this asks once.
// A notification whose answer took longer than a few seconds is not shown: the daemon has shown
// it another way meanwhile.
var status = UNAuthorizationStatus.notDetermined
_ = wait(5) { finish in
    center.getNotificationSettings { s in
        status = s.authorizationStatus
        finish()
    }
}
if status == .notDetermined {
    var granted = false
    var failure: Error?
    let asked = Date()
    let answered = wait(600) { finish in
        center.requestAuthorization(options: [.alert, .sound]) { ok, err in
            granted = ok
            failure = err
            finish()
        }
    }
    if let failure {
        // e.g. the app is in a temporary folder, which macOS does not register
        FileHandle.standardError.write("authorization: \(failure.localizedDescription)\n".data(using: .utf8)!)
        exit(5)
    }
    if !answered { exit(4) }
    if !granted { exit(3) }
    if Date().timeIntervalSince(asked) > 3 { exit(4) }
} else if status == .denied {
    exit(3)
}

let content = UNMutableNotificationContent()
content.title = title
content.body = body
content.threadIdentifier = "sealctl"
if !replace {
    content.sound = .default
}
if #available(macOS 12.0, *) {
    content.interruptionLevel = .active
}
let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
var failed: Error?
let posted = wait(5) { finish in
    center.add(request) { err in
        failed = err
        finish()
    }
}
if !posted || failed != nil {
    if let failed { FileHandle.standardError.write("post: \(failed.localizedDescription)\n".data(using: .utf8)!) }
    exit(5)
}
exit(0)
