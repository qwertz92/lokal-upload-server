# Open issues

## 2026-09-28 — P3: upstream Chaquopy Gradle deprecations

Location: Chaquopy 17.0.0 Gradle plugin; details in [Android build instructions](../android/README.md#upstream-gradle-diagnostics).

Trigger: any Android build with the default strict Gradle warning gate. Chaquopy
uses four deprecated Gradle API families, including APIs removed in Gradle 10.
The current Gradle 9.8 build succeeds with the documented `--warning-mode all`
exception; application Java warnings and Android lint remain fatal. The signed
APK is unaffected. Upgrading Gradle to 10 before the plugin is fixed would break
building. Recheck on the next Chaquopy upgrade; app-specific patches or a plugin
fork are not justified for these upstream maintenance warnings.
