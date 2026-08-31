// PinDisplay.qml — Steam Deck controller PIN entry overlay.
//
// Displays the Steam Deck front SVG with:
//   · Token display centred in the Steam Deck's screen area
//   · Coloured glows on the three action buttons (Menu/QAM/View)
//   · Source label and status feedback
//   · Keyboard-fallback toggle button

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import org.deckery.authui 1.0
import org.kde.layershell 1.0 as LayerShell

ApplicationWindow {
    id: root

    // ── Layer Shell ───────────────────────────────────────────────────────────
    LayerShell.Window.layer:                 LayerShell.Window.LayerOverlay
    LayerShell.Window.anchors:               LayerShell.Window.AnchorTop
                                           | LayerShell.Window.AnchorBottom
                                           | LayerShell.Window.AnchorLeft
                                           | LayerShell.Window.AnchorRight
    LayerShell.Window.keyboardInteractivity: LayerShell.Window.KeyboardInteractivityNone

    visible:    false
    color:      "transparent"
    flags:      Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint

    // ── State ─────────────────────────────────────────────────────────────────
    property string authSource:  ""
    property var    tokens:      []
    property string statusText:  ""
    property bool   finishing:   false

    // ── DisplayClient polling ─────────────────────────────────────────────────
    Timer {
        interval: 50; repeat: true; running: true
        onTriggered: client.poll()
    }

    DisplayClient {
        id: client
        Component.onCompleted: client.start_listening()

        onSession_started: (source) => {
            root.authSource = source
            root.tokens     = []
            root.statusText = ""
            root.finishing  = false
            root.visible    = true
        }
        onToken_added:      (token) => { root.tokens = root.tokens.concat([token]) }
        onBackspace_pressed: {
            if (root.tokens.length > 0)
                root.tokens = root.tokens.slice(0, root.tokens.length - 1)
        }
        onConfirmed:  { root.statusText = "✓"; root.finishing = true }
        onCancelled:  { root.statusText = "✗"; root.finishing = true }
        onSession_ended: { hideTimer.restart() }
    }

    Timer { id: hideTimer; interval: 700; repeat: false
        onTriggered: { root.visible = false; root.tokens = []; root.finishing = false } }

    // ── Full-screen scrim ─────────────────────────────────────────────────────
    Rectangle {
        anchors.fill: parent
        color: "#99000000"          // 60 % dark scrim
        visible: root.visible

        // ── Steam Deck SVG with overlays ──────────────────────────────────────
        Item {
            id: deckView

            // Fill ~85 % of the narrower screen dimension; cap at native SVG width
            property real svgNativeW: 1024
            property real svgNativeH: 414
            property real scale:      Math.min(parent.width  * 0.88 / svgNativeW,
                                               parent.height * 0.72 / svgNativeH)
            width:  svgNativeW * scale
            height: svgNativeH * scale
            anchors.centerIn: parent

            // ── Steam Deck outline ────────────────────────────────────────────
            Image {
                anchors.fill: parent
                source:       "qrc:/qt/qml/org/deckery/authui/assets/steamdeckFront.svg"
                fillMode:     Image.PreserveAspectFit
                smooth:       true
                opacity:      root.finishing ? 0.5 : 0.85
                Behavior on opacity { NumberAnimation { duration: 200 } }
            }

            // ── Button glows ──────────────────────────────────────────────────
            // SVG button coords from deckery-hud callouts.py:
            //   BTN_SELECT (View/⊞):  (121, 33)  → backspace
            //   BTN_START  (Menu/≡):  (902, 33)  → confirm
            //   BTN_BASE   (QAM/⋯):  (845, 289) → cancel

            // View/⊞ — backspace — blue
            ButtonGlow {
                svgX: 121; svgY: 33; scale_: deckView.scale
                glowColor: "#89b4fa"; label: "⊞"
                visible: root.tokens.length > 0 && !root.finishing
            }
            // Menu/≡ — confirm — green
            ButtonGlow {
                svgX: 902; svgY: 33; scale_: deckView.scale
                glowColor: "#a6e3a1"; label: "≡"
                visible: !root.finishing
            }
            // QAM/⋯ — cancel — red
            ButtonGlow {
                svgX: 845; svgY: 289; scale_: deckView.scale
                glowColor: "#f38ba8"; label: "⋯"
                visible: !root.finishing
            }

            // ── Screen area overlay ───────────────────────────────────────────
            // The Steam Deck's display sits between the thumbsticks.
            // In SVG coords: x≈270–750, y≈20–285  (approximate — no IDs in SVG)
            Item {
                id: screenArea
                x:      270 * deckView.scale
                y:       20 * deckView.scale
                width:  480 * deckView.scale
                height: 265 * deckView.scale

                // Frosted card inside the screen boundary
                Rectangle {
                    anchors.fill: parent
                    color:        "#CC1e1e2e"    // 80 % catppuccin base
                    radius:       8 * deckView.scale
                    border.color: "#44cdd6f4"
                    border.width: 1
                }

                ColumnLayout {
                    anchors.fill:    parent
                    anchors.margins: 10 * deckView.scale
                    spacing:         6 * deckView.scale

                    // Source label
                    Text {
                        Layout.fillWidth:    true
                        text:                root.authSource
                        color:               "#89b4fa"
                        font.pixelSize:      Math.round(11 * deckView.scale)
                        font.capitalization: Font.AllUppercase
                        font.letterSpacing:  2
                        horizontalAlignment: Text.AlignHCenter
                    }

                    // Token row — one glyph box per chord pressed
                    Flow {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: Math.round(5 * deckView.scale)
                        horizontalItemAlignment: Flow.AlignHCenter

                        Repeater {
                            model: Math.max(root.tokens.length + 1, 8)

                            Rectangle {
                                property bool filled: index < root.tokens.length
                                width:  Math.round(30 * deckView.scale)
                                height: Math.round(30 * deckView.scale)
                                radius: 4 * deckView.scale
                                color:  filled ? "#313244" : "#181825"
                                border.color: filled ? "#89b4fa" : "#313244"
                                border.width: 1

                                Text {
                                    anchors.centerIn: parent
                                    text:             index < root.tokens.length
                                                          ? root.tokens[index] : ""
                                    color:            "#cdd6f4"
                                    font.pixelSize:   Math.round(11 * deckView.scale)
                                    font.family:      "monospace"
                                }
                            }
                        }
                    }

                    // Status feedback (✓ / ✗) or hint
                    Text {
                        Layout.fillWidth:    true
                        visible:             root.statusText !== ""
                        text:                root.statusText
                        color:               root.statusText === "✓" ? "#a6e3a1" : "#f38ba8"
                        font.pixelSize:      Math.round(28 * deckView.scale)
                        horizontalAlignment: Text.AlignHCenter
                    }

                    // Keyboard fallback button
                    Rectangle {
                        Layout.alignment:  Qt.AlignHCenter
                        visible:           !root.finishing
                        width:             Math.round(100 * deckView.scale)
                        height:            Math.round(22 * deckView.scale)
                        radius:            4 * deckView.scale
                        color:             kbArea.containsMouse ? "#313244" : "#1e1e2e"
                        border.color:      "#585b70"
                        border.width:      1

                        Text {
                            anchors.centerIn: parent
                            text:             "⌨  Keyboard"
                            color:            "#6c7086"
                            font.pixelSize:   Math.round(9 * deckView.scale)
                        }
                        MouseArea {
                            id:            kbArea
                            anchors.fill:  parent
                            hoverEnabled:  true
                            // TODO: signal daemon to cancel and fall through to pam_unix
                            onClicked:     client.send_ui_cancel()
                        }
                    }
                }
            }
        }
    }

    // ── ButtonGlow component ──────────────────────────────────────────────────
    // A coloured halo + label rendered at an SVG-coordinate button position.
    component ButtonGlow: Item {
    property real   svgX:       0
    property real   svgY:       0
    property real   scale_:     1.0
    property color  glowColor:  "#ffffff"
    property string label:      ""

    x:      svgX * scale_ - width  / 2
    y:      svgY * scale_ - height / 2
    width:  Math.round(28 * scale_)
    height: Math.round(28 * scale_)

    // Outer glow ring
    Rectangle {
        anchors.centerIn: parent
        width:  parent.width  * 1.8
        height: parent.height * 1.8
        radius: width / 2
        color:  "transparent"
        border.color: Qt.rgba(glowColor.r, glowColor.g, glowColor.b, 0.35)
        border.width: 2
    }
    // Filled circle
    Rectangle {
        anchors.fill: parent
        radius: width / 2
        color:  Qt.rgba(glowColor.r, glowColor.g, glowColor.b, 0.25)
        border.color: glowColor
        border.width: 1.5
    }
    // Label
    Text {
        anchors.centerIn: parent
        text:             label
        color:            glowColor
        font.pixelSize:   Math.round(9 * scale_)
        font.bold:        true
    }
    }   // ButtonGlow
}       // ApplicationWindow
