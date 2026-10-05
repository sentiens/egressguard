// EgressGuard menu bar app: status, on/off and settings for the egressguard daemon.
// The app writes only the user's own files: control.json (on/off) and
// settings.json (trusted networks, endpoints). The root daemon checks every
// entry, applies them within a second and reports what it refused.
import AppKit
import SwiftUI

let home = FileManager.default.homeDirectoryForCurrentUser
let userDir = home.appendingPathComponent("Library/Application Support/EgressGuard")
let controlURL = userDir.appendingPathComponent("control.json")
let statusURL = URL(fileURLWithPath: "/Library/Application Support/EgressGuard/status.json")

// MARK: - Files

/// A file that is not what it should be.
struct FileProblem: LocalizedError {
    let description: String
    var errorDescription: String? { description }
}

/// The JSON object in the file at url; nil if there is no such file.
func readJSON(_ url: URL) throws -> [String: Any]? {
    let data: Data
    do {
        data = try Data(contentsOf: url)
    } catch CocoaError.fileReadNoSuchFile {
        return nil
    }
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw FileProblem(description: "\(url.lastPathComponent) is not a JSON object")
    }
    return object
}

/// The list under key in json, empty if absent; anything but such a list is an error.
func list<Element>(_ json: [String: Any], _ key: String) throws -> [Element] {
    guard let value = json[key] else { return [] }
    guard let items = value as? [Element] else { throw FileProblem(description: "\(key) is not a list, or has an entry of the wrong kind") }
    return items
}

/// When the file at url last changed; nil if there is no such file.
func modified(_ url: URL) throws -> Date? {
    do {
        return try FileManager.default.attributesOfItem(atPath: url.path)[.modificationDate] as? Date
    } catch CocoaError.fileReadNoSuchFile {
        return nil
    }
}

/// Replaces the file at url with value as JSON; returns what went wrong, if anything.
@discardableResult
func writeAtomically(_ value: [String: Any], to url: URL) -> String? {
    do {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url, options: .atomic)
        return nil
    } catch {
        NSLog("EgressGuard: %@ not written: %@", url.path, error.localizedDescription)
        return "\(url.lastPathComponent) not written: \(error.localizedDescription)"
    }
}

@discardableResult
func writeControl(_ value: [String: Any]) -> String? { writeAtomically(value, to: controlURL) }

// MARK: - Status

struct Uplink {
    var name: String
    var router: String
    var mac: String?
    var network: String?
}

struct Status {
    var state = "unknown"
    var mode = "on"
    var until: Double?
    var tunnel: String?
    var networks: [String] = []
    var sealed = false
    var enforced = true
    var stale = true
    var problems: [String] = []
    var uplinks: [Uplink] = []
    var endpoints: [(endpoint: String, source: String)] = []
    var settingsPath: String?
}

func readStatus() -> Status {
    var result = Status()
    let json: [String: Any]
    do {
        guard let found = try readJSON(statusURL) else { return result } // no daemon: stale
        json = found
    } catch {
        result.problems.append("\(statusURL.path): \(error.localizedDescription)")
        return result
    }
    result.state = json["state"] as? String ?? "unknown"
    result.mode = json["mode"] as? String ?? "on"
    result.until = json["until"] as? Double
    result.sealed = json["sealed"] as? Bool ?? false
    result.enforced = json["enforced"] as? Bool ?? true
    if let tunnel = json["tunnel"] as? [String: Any] {
        let services = tunnel["services"] as? [String] ?? []
        result.tunnel = services.isEmpty ? tunnel["interface"] as? String : services.joined(separator: ", ")
    }
    if let trusted = json["trusted"] as? [[String: Any]] {
        result.networks = Array(Set(trusted.compactMap { $0["network"] as? String })).sorted()
    }
    for (name, value) in (json["uplinks"] as? [String: [String: Any]] ?? [:]).sorted(by: { $0.key < $1.key }) {
        guard let router = value["router"] as? String else { continue }
        result.uplinks.append(Uplink(name: name, router: router, mac: value["mac"] as? String,
                                     network: (value["trusted"] as? Bool ?? false) ? value["network"] as? String : nil))
    }
    for entry in json["endpoints"] as? [[String: Any]] ?? [] {
        if let endpoint = entry["endpoint"] as? String {
            result.endpoints.append((endpoint, entry["source"] as? String ?? ""))
        }
    }
    result.settingsPath = json["settings"] as? String
    let updated = json["updated"] as? Double ?? 0
    result.stale = Date().timeIntervalSince1970 - updated > 30
    if let note = json["note"] as? String { result.problems.append(note) }
    result.problems += json["errors"] as? [String] ?? []
    return result
}

// MARK: - Endpoints

/// Why text is not an endpoint address the daemon accepts ("1.2.3.4:443",
/// "[2001:db8::1]:51820", "2001:db8::1"), or nil if it is.
func endpointProblem(_ text: String) -> String? {
    var host = text
    var port: String?
    if text.hasPrefix("[") {
        guard let close = text.firstIndex(of: "]") else { return "a bracketed address needs its closing ]" }
        host = String(text[text.index(after: text.startIndex)..<close])
        let rest = text[text.index(after: close)...]
        if !rest.isEmpty {
            guard rest.hasPrefix(":") else { return "write [address]:port" }
            port = String(rest.dropFirst())
        }
    } else if text.filter({ $0 == ":" }).count == 1 {
        let parts = text.split(separator: ":", omittingEmptySubsequences: false)
        host = String(parts[0])
        port = String(parts[1])
    }
    var v4 = in_addr(), v6 = in6_addr()
    let isV4 = inet_pton(AF_INET, host, &v4) == 1, isV6 = inet_pton(AF_INET6, host, &v6) == 1
    guard isV4 || isV6 else {
        return "An IP address, optionally with a port: 203.0.113.5:443 or [2001:db8::1]:51820. "
            + "Not a host name: it cannot be resolved while the network is closed."
    }
    if isV4 && (host == "0.0.0.0" || host.split(separator: ".").first.flatMap { Int($0) }.map { (224...239).contains($0) } == true) {
        return "not a unicast address"
    }
    if isV6 && (host == "::" || host.lowercased().hasPrefix("ff")) {
        return "not a unicast address"
    }
    if let port = port {
        guard let number = Int(port), port.allSatisfy(\.isNumber), (1...65535).contains(number) else {
            return "the port is a number from 1 to 65535"
        }
    }
    return nil
}

// MARK: - Settings

struct TrustedNetwork: Identifiable {
    let id = UUID()
    let json: [String: Any] // as the settings file has it

    var name: String { json["name"] as? String ?? "?" }
    var detail: String {
        [(json["interface"] as? String).map { "interface \($0)" }, json["router"] as? String, json["router_mac"] as? String]
            .compactMap { $0 }.joined(separator: " · ")
    }

    /// Whether item in a settings file is this network.
    func matches(_ item: [String: Any]) -> Bool {
        ["name", "router", "router_mac", "interface"].allSatisfy { key in
            (item[key] as? String) == (json[key] as? String)
        }
    }
}

final class SettingsModel: ObservableObject {
    @Published var networks: [TrustedNetwork] = []
    @Published var endpoints: [String] = []
    @Published var learnVPN = true
    @Published var learnConnections = false
    @Published var vpnOnly = false
    @Published var status = Status()
    @Published var newName = ""
    @Published var newEndpoint = ""
    @Published var newProto = "tcp"
    @Published var inputError: String?
    @Published var saveError: String?
    var url: URL { status.settingsPath.map { URL(fileURLWithPath: $0) } ?? userDir.appendingPathComponent("settings.json") }
    private var timer: Timer?

    init() {
        status = readStatus()
        load()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.status = readStatus() }
    }

    /// Stops the status refresh; the window is closing.
    func stop() {
        timer?.invalidate()
        timer = nil
    }

    func load() {
        do {
            let json = try readJSON(url) ?? [:]
            networks = try list(json, "trusted_networks").map { TrustedNetwork(json: $0) }
            endpoints = try list(json, "endpoints")
            learnVPN = json["learn_vpn_services"] as? Bool ?? true
            learnConnections = json["learn_connections"] as? Bool ?? false
            vpnOnly = json["vpn_only"] as? Bool ?? false
        } catch {
            saveError = "\(url.lastPathComponent) cannot be read: \(error.localizedDescription); fix or delete it"
        }
    }

    /// Applies one change to the settings file as it is now, so edits made elsewhere
    /// (the CLI) are kept and settings the user never touched stay unset. If the file
    /// changes meanwhile, the change is applied again; a file that is not a JSON
    /// object is never overwritten.
    func update(_ change: (inout [String: Any]) throws -> Void) {
        defer {
            if saveError == nil { load() }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in self?.status = readStatus() }
        }
        do {
            for _ in 0..<3 {
                let before = try modified(url)
                var json = try readJSON(url) ?? ["version": 1]
                try change(&json)
                guard try modified(url) == before else { continue }
                saveError = writeAtomically(json, to: url)
                return
            }
            saveError = "\(url.lastPathComponent) keeps changing; try again"
        } catch {
            saveError = "\(url.lastPathComponent): \(error.localizedDescription); fix or delete it (nothing was changed)"
        }
    }

    func setting(_ key: String) -> Binding<Bool> {
        Binding(
            get: { [weak self] in
                switch key {
                case "learn_vpn_services": return self?.learnVPN ?? true
                case "learn_connections": return self?.learnConnections ?? false
                default: return self?.vpnOnly ?? false
                }
            },
            set: { [weak self] value in self?.update { $0[key] = value } })
    }

    /// The current uplink with a known router and MAC that is not trusted yet.
    var candidate: Uplink? { status.uplinks.first { $0.mac != nil && $0.network == nil } }
    var trustedNow: Uplink? { status.uplinks.first { $0.network != nil } }

    func trustCurrent() {
        guard let uplink = candidate, let mac = uplink.mac else { return }
        let typed = newName.trimmingCharacters(in: .whitespaces)
        let network: [String: Any] = ["name": typed.isEmpty ? "Network \(uplink.router)" : typed,
                                      "router": uplink.router, "router_mac": mac]
        update { $0["trusted_networks"] = try list($0, "trusted_networks") as [[String: Any]] + [network] }
        newName = ""
    }

    func remove(_ network: TrustedNetwork) {
        update { json in
            json["trusted_networks"] = try (list(json, "trusted_networks") as [[String: Any]]).filter { !network.matches($0) }
        }
    }

    func addEndpoint() {
        let text = newEndpoint.trimmingCharacters(in: .whitespaces)
        if let problem = endpointProblem(text) {
            inputError = problem
            return
        }
        let full = "\(text)/\(newProto)"
        update { json in
            let current: [String] = try list(json, "endpoints")
            if !current.contains(full) { json["endpoints"] = current + [full] }
        }
        newEndpoint = ""
        inputError = nil
    }

    func removeEndpoint(_ endpoint: String) {
        update { $0["endpoints"] = try (list($0, "endpoints") as [String]).filter { $0 != endpoint } }
    }

    var vpnProfileCount: Int { status.endpoints.filter { $0.source.contains("vpn: ") }.count }
    var learnedCount: Int { status.endpoints.filter { $0.source.contains("connection: ") }.count }
}

struct SettingsView: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                section("Trusted networks", "Direct internet here. A network is recognised by its router's address and MAC address.") {
                    if model.networks.isEmpty {
                        Text("None yet: outside a tunnel there is no internet anywhere.").foregroundColor(.secondary)
                    }
                    ForEach(model.networks) { network in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(network.name)
                                Text(network.detail).font(.caption).foregroundColor(.secondary)
                            }
                            Spacer()
                            Button("Remove") { model.remove(network) }
                        }
                    }
                    Divider()
                    if let uplink = model.candidate {
                        Text("Now: \(uplink.name), router \(uplink.router) · \(uplink.mac ?? "")").font(.caption)
                        HStack {
                            TextField("Name, e.g. Home", text: $model.newName)
                            Button("Trust this network") { model.trustCurrent() }
                        }
                    } else if let uplink = model.trustedNow {
                        Text("This network is already trusted: \(uplink.network ?? "")").font(.caption).foregroundColor(.secondary)
                    } else {
                        Text("No current network to trust (no router, or its MAC is unknown).").font(.caption).foregroundColor(.secondary)
                    }
                }

                section("Ways out on other networks",
                        "Outside trusted networks the Mac may only reach these servers, so a VPN can bring its tunnel up; everything else goes through the tunnel or nowhere.") {
                    Toggle("VPN configurations in macOS, automatically (servers now: \(model.vpnProfileCount))",
                           isOn: model.setting("learn_vpn_services"))
                    Toggle("Learn the servers VPN apps connect to on a trusted network (learned: \(model.learnedCount))",
                           isOn: model.setting("learn_connections"))
                    Text("Your own endpoints, always allowed").font(.subheadline)
                    ForEach(model.endpoints, id: \.self) { endpoint in
                        HStack {
                            Text(endpoint).font(.system(.body, design: .monospaced))
                            Spacer()
                            Button("Remove") { model.removeEndpoint(endpoint) }
                        }
                    }
                    HStack {
                        TextField("address:port, e.g. 203.0.113.5:443", text: $model.newEndpoint)
                        Picker("", selection: $model.newProto) {
                            Text("TCP").tag("tcp")
                            Text("UDP").tag("udp")
                        }.frame(width: 90)
                        Button("Add") { model.addEndpoint() }
                    }
                    if let error = model.inputError {
                        Text(error).font(.caption).foregroundColor(.red)
                    }
                }

                section("Mode", "") {
                    Toggle("No trusted networks: VPN only, even at home", isOn: model.setting("vpn_only"))
                }

                if let error = model.saveError {
                    Text("⚠︎ " + error).font(.caption).foregroundColor(.red)
                }
                if !model.status.problems.isEmpty || !model.status.enforced {
                    section("The daemon reports", "") {
                        if !model.status.enforced {
                            Text("⚠︎ The rules are not in force").font(.caption).foregroundColor(.red)
                        }
                        ForEach(model.status.problems, id: \.self) { problem in
                            Text("⚠︎ " + problem).font(.caption).foregroundColor(.orange)
                        }
                    }
                }
                Text("Settings file: \(model.url.path)").font(.caption2).foregroundColor(.secondary)
            }
            .padding(20)
        }
        .frame(minWidth: 560, minHeight: 520)
    }

    @ViewBuilder
    func section<Content: View>(_ title: String, _ note: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.headline)
            if !note.isEmpty { Text(note).font(.caption).foregroundColor(.secondary) }
            content()
        }
    }
}

// MARK: - Menu bar

final class Controller: NSObject, NSApplicationDelegate, NSWindowDelegate {
    let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let menu = NSMenu()
    var timer: Timer?
    var settingsWindow: NSWindow?
    var settingsModel: SettingsModel?
    var controlError: String?

    func applicationDidFinishLaunching(_ notification: Notification) {
        item.menu = menu
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func time(_ epoch: Double) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: Date(timeIntervalSince1970: epoch))
    }

    func refresh() {
        let status = readStatus()
        let symbol: String
        let line: String
        switch (status.stale, status.state) {
        case (true, _):
            symbol = "exclamationmark.shield"; line = "The EgressGuard daemon does not answer"
        case (_, "trusted"):
            let names = status.networks.joined(separator: ", ")
            symbol = "lock.shield"; line = "On · trusted network (\(names)), direct"
        case (_, "tunnel"):
            symbol = "lock.shield.fill"; line = "On · through the tunnel (\(status.tunnel ?? "?"))"
        case (_, "blocked") where status.sealed:
            symbol = "moon.zzz"; line = "On · closed since sleep, until a full wake"
        case (_, "blocked"):
            symbol = "xmark.shield.fill"; line = "On · no internet: connect a VPN"
        case (_, "off"):
            symbol = "shield.slash"
            line = status.until.map { "Off until \(time($0))" } ?? "Off"
        default:
            symbol = "questionmark.diamond"; line = "State: \(status.state)"
        }
        item.button?.image = NSImage(systemSymbolName: status.enforced ? symbol : "exclamationmark.shield",
                                     accessibilityDescription: line)
        item.button?.toolTip = "EgressGuard: " + line

        menu.removeAllItems()
        menu.addItem(withTitle: line, action: nil, keyEquivalent: "")
        if status.mode == "lock" { menu.addItem(withTitle: "Self-test running", action: nil, keyEquivalent: "") }
        if !status.stale && !status.enforced { menu.addItem(withTitle: "⚠︎ The rules are not in force", action: nil, keyEquivalent: "") }
        if let error = controlError { menu.addItem(withTitle: "⚠︎ " + error, action: nil, keyEquivalent: "") }
        for problem in status.problems { menu.addItem(withTitle: "⚠︎ " + problem, action: nil, keyEquivalent: "") }
        menu.addItem(.separator())
        if status.mode == "off" {
            add("Turn on", #selector(turnOn))
        }
        if status.mode != "off" || status.until != nil {
            add("Turn off for 15 minutes", #selector(off15))
            add("Turn off for 1 hour", #selector(off60))
            add("Turn off until turned on", #selector(offForever))
        }
        menu.addItem(.separator())
        add("Settings…", #selector(openSettings))
    }

    func add(_ title: String, _ action: Selector) {
        let entry = NSMenuItem(title: title, action: action, keyEquivalent: "")
        entry.target = self
        menu.addItem(entry)
    }

    func control(_ value: [String: Any]) {
        controlError = writeControl(value)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { [weak self] in self?.refresh() }
    }

    func off(minutes: Int?) {
        var value: [String: Any] = ["mode": "off"]
        if let minutes = minutes { value["until"] = Int(Date().timeIntervalSince1970) + minutes * 60 }
        control(value)
    }

    @objc func openSettings() {
        if settingsWindow == nil {
            let model = SettingsModel()
            let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 640),
                                  styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
            window.title = "EgressGuard Settings"
            window.contentView = NSHostingView(rootView: SettingsView(model: model))
            window.isReleasedWhenClosed = false
            window.delegate = self
            window.center()
            (settingsWindow, settingsModel) = (window, model)
        }
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow?.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        settingsModel?.stop()
        (settingsWindow, settingsModel) = (nil, nil) // a fresh model next time reads the file again
    }

    @objc func turnOn() { control(["mode": "on"]) }
    @objc func off15() { off(minutes: 15) }
    @objc func off60() { off(minutes: 60) }
    @objc func offForever() { off(minutes: nil) }
}

#if !EGRESSGUARD_PREVIEW // the preview build renders the settings window to a picture instead
let app = NSApplication.shared
let controller = Controller()
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
#endif
