import AppKit
import SwiftUI

/// `swift run` starts a bare executable: without this it has no Dock icon and no focus.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

@main
struct SealPDFApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.openWindow) private var openWindow

    var body: some Scene {
        WindowGroup(AppInfo.name) {
            ContentView()
        }
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About \(AppInfo.name)") { openWindow(id: "about") }
            }
        }

        Window("About \(AppInfo.name)", id: "about") {
            AboutView()
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
    }
}
