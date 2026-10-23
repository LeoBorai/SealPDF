import SwiftUI
import UniformTypeIdentifiers

/// The Sign tab: open a PDF, pick a certificate, sign.
struct SignView: View {
    @ObservedObject var model: SignModel
    /// Switches to the Verify tab with the PDF that is open here.
    let openInVerify: @MainActor () -> Void

    var body: some View {
        HStack(spacing: 0) {
            controls
                .frame(width: 320)
                .padding(20)
            Divider()
            preview
        }
        .frame(minWidth: 780, minHeight: 520)
        .alert(
            "Something went wrong",
            isPresented: Binding(
                get: { model.failure != nil },
                set: { if !$0 { model.failure = nil } }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.failure ?? "")
        }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Document") {
                VStack(alignment: .leading, spacing: 8) {
                    Button("Open PDF…") { model.chooseFile() }
                    Text(model.input?.lastPathComponent ?? "No PDF chosen")
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            if model.previouslySigned {
                Button {
                    openInVerify()
                } label: {
                    Label(
                        "This PDF was previously signed, go to Verify for details",
                        systemImage: "info.circle"
                    )
                    .multilineTextAlignment(.leading)
                }
                .buttonStyle(.link)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            }

            GroupBox("Certificate") {
                VStack(alignment: .leading, spacing: 10) {
                    Picker("Source", selection: $model.source) {
                        Text("Keychain").tag(CertificateSource.keychain)
                        Text("File").tag(CertificateSource.file)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    if model.source == .file {
                        fileControls
                    }

                    Picker("Sign with", selection: $model.selected) {
                        ForEach(model.aliases, id: \.self) { Text($0).tag($0) }
                    }
                    .disabled(model.aliases.isEmpty)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            Button("Sign…") { Task { await model.sign() } }
                .controlSize(.large)
                .keyboardShortcut(.defaultAction)
                .disabled(!model.canSign)

            Text(model.status)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)

            Spacer()
        }
    }

    private var fileControls: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button("Choose .p12 / .pfx…") { model.chooseCertificateFile() }
            Text(model.certificateFile?.lastPathComponent ?? "No file chosen")
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            if model.certificateFile != nil {
                SecureField("Password", text: $model.password)
                    .onSubmit { Task { await model.unlockCertificateFile() } }
                Button("Unlock") { Task { await model.unlockCertificateFile() } }
                    .disabled(!model.canUnlock)
            }
        }
    }

    private var preview: some View {
        PreviewPane(url: model.input, onDrop: model.setInput)
    }
}
