import AppKit
import SwiftUI

struct AboutView: View {
    var body: some View {
        VStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 128, height: 128)

            Text(AppInfo.name)
                .font(.system(size: 28, weight: .bold))

            Text(AppInfo.summary)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow {
                    Text("Version").gridColumnAlignment(.trailing)
                    Text(AppInfo.version)
                        .font(.system(.body, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                if let commit = AppInfo.commit {
                    GridRow {
                        Text("Commit")
                        Link(String(commit.prefix(9)), destination: AppInfo.commitURL(commit))
                            .font(.system(.body, design: .monospaced))
                    }
                }
            }
            .padding(.top, 6)

            Button("GitHub") { NSWorkspace.shared.open(AppInfo.repository) }
                .padding(.top, 8)
        }
        .padding(.horizontal, 40)
        .padding(.top, 36)
        .padding(.bottom, 24)
        .frame(width: 320)
    }
}
