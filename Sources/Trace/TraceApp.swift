import SwiftUI

@main
struct TraceApp: App {
    @State private var store = ScanStore()

    var body: some Scene {
        WindowGroup {
            MainView()
                .environment(store)
                .frame(minWidth: 760, minHeight: 520)
        }
        .defaultSize(width: 900, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open File…") {
                    store.chooseFile()
                }
                .keyboardShortcut("o")
            }
        }

        Settings {
            SettingsView()
                .frame(width: 520, height: 300)
        }
    }
}
