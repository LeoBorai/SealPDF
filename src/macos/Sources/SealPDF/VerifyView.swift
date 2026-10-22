import SwiftUI

/// The Verify tab: open a PDF, see its signatures and whether it can be accepted as signed.
struct VerifyView: View {
    @ObservedObject var model: VerifyModel

    var body: some View {
        HStack(spacing: 0) {
            controls
                .frame(width: 320)
                .padding(20)
            Divider()
            PreviewPane(url: model.input, onDrop: model.open)
        }
        .frame(minWidth: 780, minHeight: 520)
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

            if model.isWorking {
                ProgressView("Checking signatures…")
            } else if let failure = model.failure {
                Text(failure)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let report = model.report {
                ReportView(report: report)
            }

            Spacer()
        }
    }
}

/// The result of checking one PDF.
private struct ReportView: View {
    let report: Report

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if !report.hasSignatures {
                    Text("This PDF is not signed.")
                        .font(.headline)
                }

                GroupBox("Verdict") {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(report.verdicts, id: \.self) { VerdictRow(verdict: $0) }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(4)
                }

                if !report.signatures.isEmpty {
                    GroupBox("Signatures") {
                        VStack(alignment: .leading, spacing: 12) {
                            ForEach(Array(report.signatures.enumerated()), id: \.offset) { _, signature in
                                SignatureRow(signature: signature, revisions: report.revisions)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                    }
                }

                Text("Certificate trust and revocation were not checked.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct VerdictRow: View {
    let verdict: Verdict

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(color)
            VStack(alignment: .leading, spacing: 2) {
                Text(verdict.verdict == "OK" ? "Signed and intact" : verdict.text)
                    .fontWeight(.medium)
                if let meaning = verdict.meaning {
                    Text(meaning)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var symbol: String {
        switch verdict.verdict {
        case "OK": return "checkmark.seal.fill"
        case "KO": return "xmark.seal.fill"
        default: return "questionmark.circle.fill"
        }
    }

    private var color: Color {
        switch verdict.verdict {
        case "OK": return .green
        case "KO": return .red
        default: return .orange
        }
    }
}

private struct SignatureRow: View {
    let signature: SignatureInfo
    let revisions: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .fontWeight(.medium)
            if let when = signature.signedAtText {
                Text(when)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text("Covers revision \(signature.revision) of \(revisions)")
                .font(.callout)
                .foregroundStyle(.secondary)
            if let reason = signature.reason {
                Text("Reason: \(reason)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Text(signature.isIntact ? "Intact" : signature.status.joined(separator: ", "))
                .font(.callout)
                .foregroundStyle(signature.isIntact ? Color.green : Color.red)
        }
    }

    private var title: String {
        if signature.docTimestamp { return "Document timestamp" }
        return signature.signer ?? "Unknown signer"
    }
}
