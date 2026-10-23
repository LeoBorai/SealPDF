import SwiftUI

/// The window: a Sign tab and a Verify tab, each with its own PDF and preview.
struct ContentView: View {
    enum Tab: Hashable {
        case sign
        case verify
    }

    /// Which tab is showing. An object, not `@State`: that is a macro in the newest SDKs, and
    /// the command line tools alone cannot expand it.
    @MainActor
    final class Selection: ObservableObject {
        @Published var tab: Tab = .sign
    }

    @StateObject private var sign = SignModel()
    @StateObject private var verify = VerifyModel()
    @StateObject private var selection = Selection()

    var body: some View {
        // A segmented picker, not `TabView`: on macOS that draws a box whose border runs
        // through the tab control.
        VStack(spacing: 0) {
            Picker("", selection: $selection.tab) {
                Text("Sign").tag(Tab.sign)
                Text("Verify").tag(Tab.verify)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 200)
            .padding(.vertical, 10)

            Divider()

            switch selection.tab {
            case .sign:
                SignView(model: sign, openInVerify: openSignedPDFInVerify)
            case .verify:
                VerifyView(model: verify)
            }
        }
    }

    /// The notice on the Sign tab: hand its PDF to Verify, which checks it now.
    private func openSignedPDFInVerify() {
        guard let url = sign.input else { return }
        verify.open(url)
        selection.tab = .verify
    }
}
