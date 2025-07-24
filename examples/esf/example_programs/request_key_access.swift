import Foundation
import AppKit

func requestAccessibilityPermission() {
    let options: NSDictionary = [kAXTrustedCheckOptionPrompt.takeRetainedValue() as NSString: true]
    let accessEnabled = AXIsProcessTrustedWithOptions(options)
    if accessEnabled {
        print("Accessibility permission already granted.")
    } else {
        print("Requested Accessibility permission. Please enable it in System Preferences > Security & Privacy > Privacy > Accessibility.")
    }
}

requestAccessibilityPermission()
RunLoop.main.run(until: Date(timeIntervalSinceNow: 5))