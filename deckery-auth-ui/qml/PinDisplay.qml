// PinDisplay.qml — Controller PIN entry overlay.
//
// Subscribes to DisplayClient (Rust QObject) and renders:
//   · Source label  ("sudo", "polkit", …)
//   · Token row     (one glyph per button chord pressed)
//   · Status line   (idle / confirming / cancelled)
//
// The window is a Wayland Layer Shell surface (Overlay layer, full-screen
// anchor) that stays hidden until a SESSION_START event arrives.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import org.deckery.authui 1.0
import org.kde.layershell 1.0 as LayerShell

ApplicationWindow {
    id: root

    // ── Layer Shell configuration ─────────────────────────────────────────────
    // Anchor all edges → full-screen canvas; the visible content is a small
    // centred card. This lets us dim the whole screen behind the card later.
    LayerShell.Window.layer:                 LayerShell.Window.LayerOverlay
    LayerShell.Window.anchors:               LayerShell.Window.AnchorAll
    LayerShell.Window.keyboardInteractivity: LayerShell.Window.KeyboardInteractivityNone
    // We do not need keyboard input — controller only.  If the password
    // fallback mode is added later, switch to KeyboardInteractivityOnDemand.

    visible:    false   // hidden until SESSION_START
    color:      "transparent"
    flags:      Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint

    // ── State ─────────────────────────────────────────────────────────────────
    property string authSource:  ""          // "sudo", "polkit", …
    property var    tokens:      []          // encoded token strings
    property string statusText:  ""          // feedback line
    property bool   finishing:   false       // brief visual hold before hiding

    // ── DisplayClient connection ──────────────────────────────────────────────
    DisplayClient {
        id: client

        Component.onCompleted: client.startListening()

        // Poll the Rust event queue every 50 ms on the Qt main thread.
        Timer {
            interval: 50
            repeat:   true
            running:  true
            onTriggered: client.poll()
        }

        onSessionStarted: (source) => {
            root.authSource = source
            root.tokens     = []
            root.statusText = ""
            root.finishing  = false
            root.visible    = true
        }

        onTokenAdded: (token) => {
            root.tokens = root.tokens.concat([token])
        }

        onBackspacePressed: {
            if (root.tokens.length > 0)
                root.tokens = root.tokens.slice(0, root.tokens.length - 1)
        }

        onConfirmed: {
            root.statusText = "✓"
            root.finishing  = true
        }

        onCancelled: {
            root.statusText = "✗"
            root.finishing  = true
        }

        onSessionEnded: {
            // Small delay so the user sees the ✓/✗ before the overlay hides.
            hideTimer.restart()
        }
    }

    Timer {
        id:       hideTimer
        interval: 600
        repeat:   false
        onTriggered: {
            root.visible   = false
            root.tokens    = []
            root.finishing = false
        }
    }

    // ── Background dim ────────────────────────────────────────────────────────
    Rectangle {
        anchors.fill: parent
        color:        "#80000000"   // 50 % black scrim
        visible:      root.visible

        // ── Auth card ─────────────────────────────────────────────────────────
        Rectangle {
            anchors.centerIn: parent
            width:  420
            height: contentCol.implicitHeight + 48
            radius: 16
            color:  "#1e1e2e"       // dark navy — replace with theme colour later

            ColumnLayout {
                id:               contentCol
                anchors.centerIn: parent
                width:            parent.width - 48
                spacing:          16

                // ── Source label ──────────────────────────────────────────────
                Text {
                    Layout.fillWidth: true
                    text:             "Authentication — " + root.authSource
                    color:            "#cdd6f4"
                    font.pixelSize:   15
                    font.weight:      Font.Medium
                    horizontalAlignment: Text.AlignHCenter
                }

                // ── Token row ─────────────────────────────────────────────────
                // Each pressed chord becomes one glyph box.
                // Empty boxes fill remaining slots up to a minimum of 6.
                Flow {
                    Layout.fillWidth: true
                    spacing:          8

                    Repeater {
                        model: Math.max(root.tokens.length + 1, 6)

                        Rectangle {
                            width:  44
                            height: 44
                            radius: 8
                            color:  index < root.tokens.length
                                        ? "#313244"   // filled slot
                                        : "#181825"   // empty slot
                            border.color: index < root.tokens.length
                                        ? "#89b4fa"   // blue accent
                                        : "#45475a"
                            border.width: 1

                            Text {
                                anchors.centerIn: parent
                                text:  index < root.tokens.length
                                           ? root.tokens[index]
                                           : ""
                                color: "#cdd6f4"
                                font.pixelSize: 13
                                font.family:    "monospace"
                            }
                        }
                    }
                }

                // ── Status / feedback line ────────────────────────────────────
                Text {
                    Layout.fillWidth: true
                    text:             root.statusText
                    color:            root.statusText === "✓" ? "#a6e3a1"   // green
                                    : root.statusText === "✗" ? "#f38ba8"   // red
                                    : "transparent"
                    font.pixelSize:   22
                    horizontalAlignment: Text.AlignHCenter
                    visible:          root.statusText !== ""
                }

                // ── Hint ──────────────────────────────────────────────────────
                Text {
                    Layout.fillWidth: true
                    text:             "Press Start / ⊙ to confirm · Menu / ☰ to cancel"
                    color:            "#6c7086"
                    font.pixelSize:   11
                    horizontalAlignment: Text.AlignHCenter
                    visible:          !root.finishing
                }

                // ── Cancel button (touch / mouse fallback) ─────────────────────
                // The primary cancel path is the controller (Menu / ☰ button).
                // This button provides a pointer-device fallback — useful during
                // development and on non-Steam-Deck targets.
                Rectangle {
                    Layout.alignment:  Qt.AlignHCenter
                    width:             120
                    height:            36
                    radius:            8
                    color:             cancelArea.containsMouse ? "#3d2020" : "#2a1a1a"
                    border.color:      "#f38ba8"
                    border.width:      1
                    visible:           !root.finishing

                    Text {
                        anchors.centerIn: parent
                        text:             "Cancel"
                        color:            "#f38ba8"
                        font.pixelSize:   13
                    }

                    MouseArea {
                        id:            cancelArea
                        anchors.fill:  parent
                        hoverEnabled:  true
                        onClicked:     client.send_ui_cancel()
                    }
                }
            }
        }
    }
}
