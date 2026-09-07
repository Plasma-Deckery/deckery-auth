// PinDisplay.qml — Steam Deck controller PIN entry overlay.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import org.deckery.authui 1.0
import org.kde.layershell 1.0 as LayerShell

ApplicationWindow {
    id: root

    // ── Layer Shell ───────────────────────────────────────────────────────────
    LayerShell.Window.layer:                 LayerShell.Window.LayerTop
    LayerShell.Window.anchors:               LayerShell.Window.AnchorTop
                                           | LayerShell.Window.AnchorBottom
                                           | LayerShell.Window.AnchorLeft
                                           | LayerShell.Window.AnchorRight
    LayerShell.Window.keyboardInteractivity: root.passwordMode
                                           ? LayerShell.Window.KeyboardInteractivityOnDemand
                                           : LayerShell.Window.KeyboardInteractivityNone
    LayerShell.Window.exclusionZone:         -1

    visible:    false
    color:      "transparent"
    flags:      Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint

    // ── State ─────────────────────────────────────────────────────────────────
    property string authSource:   ""
    property var    tokens:       []
    property string statusText:   ""
    property bool   finishing:    false
    property bool   showTokens:   true
    property bool   passwordMode: false   // true = keyboard input overlay
    // Set-PIN mode — active when daemon sends SET_PIN_START.
    property bool   setPinMode:   false
    property int    setPinPhase:  1       // 1 = enter, 2 = confirm

    // ── DisplayClient polling ─────────────────────────────────────────────────
    Timer {
        interval: 50; repeat: true; running: true
        onTriggered: client.poll()
    }

    DisplayClient {
        id: client
        Component.onCompleted: client.start_listening()

        onSession_started: (source) => {
            console.log("SESSION_STARTED:", source)
            hideTimer.stop()
            root.authSource   = source
            root.tokens       = []
            root.statusText   = ""
            root.finishing    = false
            root.showTokens   = true
            root.passwordMode = false
            root.visible      = true
        }
        onToken_added:      (token) => { root.tokens = root.tokens.concat([token]) }
        onBackspace_pressed: {
            if (root.tokens.length > 0)
                root.tokens = root.tokens.slice(0, root.tokens.length - 1)
        }
        onConfirmed:  { root.statusText = "✓"; root.finishing = true }
        onCancelled:  { root.statusText = "✗"; root.finishing = true }
        onWrong_password: {
            root.tokens     = []
            root.statusText = "✗"
            wrongFlashTimer.restart()
        }
        onSession_ended: { hideTimer.restart() }

        // ── Set-PIN signals ───────────────────────────────────────────────────
        onSet_pin_started: {
            console.log("SET_PIN_STARTED")
            hideTimer.stop()
            root.setPinMode   = true
            root.setPinPhase  = 1
            root.tokens       = []
            root.statusText   = ""
            root.finishing    = false
            root.showTokens   = true
            root.passwordMode = false
            root.visible      = true
        }
        onSet_pin_phase2: {
            root.setPinPhase = 2
            root.tokens      = []
            root.statusText  = ""
        }
        onSet_pin_mismatch: {
            root.tokens     = []
            root.statusText = "✗"
            root.setPinPhase = 1
            wrongFlashTimer.restart()
        }
        onSet_pin_done: {
            root.statusText = "✓"
            root.finishing  = true
            hideTimer.restart()
        }
        onSet_pin_cancelled: {
            root.statusText = "✗"
            root.finishing  = true
            hideTimer.restart()
        }
        onSet_pin_error: (message) => {
            console.log("SET_PIN_ERROR:", message)
            root.statusText = "✗"
            root.finishing  = true
            hideTimer.restart()
        }
    }

    Timer { id: hideTimer; interval: 700; repeat: false
        onTriggered: {
            root.visible      = false
            root.tokens       = []
            root.finishing    = false
            root.passwordMode = false
            root.setPinMode   = false
            root.setPinPhase  = 1
        }
    }

    // Brief ✗ flash on wrong PIN / password — clears after 700 ms without
    // closing the overlay or setting finishing (user can retry immediately).
    Timer { id: wrongFlashTimer; interval: 700; repeat: false
        onTriggered: { if (!root.finishing) root.statusText = "" } }

    // ── Full-screen scrim ─────────────────────────────────────────────────────
    Rectangle {
        anchors.fill: parent
        color:        "#99000000"
        visible:      root.visible

        // ── Cancel (✕) — top-right ────────────────────────────────────────────
        Rectangle {
            anchors.top:     parent.top
            anchors.right:   parent.right
            anchors.margins: 20
            width:  36; height: 36; radius: 18
            color:        xBtn.containsMouse ? "#50f38ba8" : "transparent"
            border.color: "#f38ba8"; border.width: 1.5
            visible: !root.finishing
            Text {
                width: parent.width; height: parent.height
                text: "✕"; color: "#f38ba8"
                font.pixelSize:      16
                font.bold:           true
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment:   Text.AlignVCenter
            }
            MouseArea {
                id: xBtn; anchors.fill: parent; hoverEnabled: true
                onClicked: client.send_ui_cancel()
            }
        }

        // ── "Deckery Auth" title — top-left, mirrors HUD style ───────────────────
        Row {
            anchors.top:         parent.top
            anchors.left:        parent.left
            anchors.topMargin:   18
            anchors.leftMargin:  22
            spacing:             7
            visible:             !root.finishing

            Text {
                text:           "Deckery"
                color:          "#ffffff"
                font.family:    "Adwaita Sans"
                font.pixelSize: 20
            }
            Text {
                text:           "AUTH"
                color:          "#ffffff"
                opacity:        0.4
                font.family:    "Adwaita Sans"
                font.pixelSize: 17
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 1
            }
        }

        // ── Main heading + switch button — above the deck graphic ─────────────
        Column {
            anchors.bottom:           deckView.top
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottomMargin:     14
            spacing:                  10
            visible:                  !root.finishing

            // Main heading — varies by mode and phase
            Text {
                anchors.horizontalCenter: parent.horizontalCenter
                text: root.setPinMode
                    ? (root.setPinPhase === 1 ? "Set new PIN" : "Confirm new PIN")
                    : ("Authentication requested by " + root.authSource)
                color:               "#cdd6f4"
                font.pixelSize:      22
                font.bold:           true
                font.capitalization: Font.AllUppercase
                font.letterSpacing:  2
            }

            // Switch to Password — hidden in set-PIN mode
            Rectangle {
                anchors.horizontalCenter: parent.horizontalCenter
                width:  180; height: 30; radius: 15
                visible:      !root.setPinMode
                color:        kbBtn.containsMouse ? "#40cdd6f4" : "#201e1e2e"
                border.color: "#585b70"; border.width: 1
                Text {
                    anchors.centerIn: parent
                    text: "⌨  Switch to Password"
                    color: "#cdd6f4"; font.pixelSize: 12
                }
                MouseArea {
                    id: kbBtn; anchors.fill: parent; hoverEnabled: true
                    onClicked: root.passwordMode = true
                }
            }
        }

        // ── Steam Deck SVG with overlays ──────────────────────────────────────
        Item {
            id: deckView
            property real svgNativeW: 1024
            property real svgNativeH: 414
            property real scale:      Math.min(parent.width  * 0.88 / svgNativeW,
                                               parent.height * 0.72 / svgNativeH)
            width:  svgNativeW * scale
            height: svgNativeH * scale
            anchors.centerIn: parent

            Image {
                anchors.fill: parent
                source:       "qrc:/qt/qml/org/deckery/authui/assets/steamdeckFront.svg"
                fillMode:     Image.PreserveAspectFit
                smooth:       true
                opacity:      root.finishing ? 0.5 : 0.85
                Behavior on opacity { NumberAnimation { duration: 200 } }
            }

            // ── Button glows ──────────────────────────────────────────────────
            ButtonGlow {
                svgX: 121; svgY: 33; scale_: deckView.scale
                glowColor: "#89b4fa"; label: "⊞"
                visible: root.tokens.length > 0 && !root.finishing
            }
            ButtonGlow {
                svgX: 902; svgY: 33; scale_: deckView.scale
                glowColor: "#a6e3a1"; label: "≡"
                visible: !root.finishing
            }
            ButtonGlow {
                svgX: 845; svgY: 289; scale_: deckView.scale
                glowColor: "#f38ba8"; label: "⋯"
                visible: !root.finishing
            }

            // ── Screen area — token boxes only ────────────────────────────────
            // SVG inner screen rect: x=242.5, y=37, w=540.6, h=339.9
            Item {
                id: screenArea
                x:      242.5 * deckView.scale
                y:       37   * deckView.scale
                width:  540.6 * deckView.scale
                height: 339.9 * deckView.scale

                // Subtle tint so tokens are readable over the SVG artwork
                Rectangle {
                    anchors.fill: parent
                    color:        "#881e1e2e"
                    radius:       6 * deckView.scale
                }

                // Eye toggle — top-right corner of screen area
                Rectangle {
                    anchors.top:         parent.top
                    anchors.right:       parent.right
                    anchors.topMargin:   6 * deckView.scale
                    anchors.rightMargin: 6 * deckView.scale
                    width:  Math.round(26 * deckView.scale)
                    height: Math.round(26 * deckView.scale)
                    radius: 4 * deckView.scale
                    color:        eyeArea.containsMouse ? "#40cdd6f4" : "transparent"
                    border.color: "#585b70"
                    border.width: 1
                    visible: !root.finishing

                    // Eye drawn with plain Rectangles — always #cdd6f4
                    Item {
                        anchors.centerIn: parent
                        width:  Math.round(18 * deckView.scale)
                        height: Math.round(11 * deckView.scale)

                        // Oval outline
                        Rectangle {
                            anchors.fill: parent
                            color:        "transparent"
                            border.color: "#cdd6f4"
                            border.width: Math.max(1, Math.round(1.5 * deckView.scale))
                            radius:       height / 2
                        }
                        // Pupil (open state)
                        Rectangle {
                            anchors.centerIn: parent
                            visible: root.showTokens
                            width:  Math.round(5 * deckView.scale)
                            height: width
                            radius: width / 2
                            color:  "#cdd6f4"
                        }
                        // Strike-through (closed state)
                        Rectangle {
                            anchors.centerIn: parent
                            visible: !root.showTokens
                            width:   parent.width * 0.75
                            height:  Math.max(1, Math.round(1.5 * deckView.scale))
                            color:   "#cdd6f4"
                            rotation: -18
                        }
                    }
                    MouseArea {
                        id:           eyeArea
                        anchors.fill: parent
                        hoverEnabled: true
                        onClicked:    root.showTokens = !root.showTokens
                    }
                }

                // Token grid — top-left, grows with input, variable-width boxes
                Flow {
                    anchors.top:         parent.top
                    anchors.left:        parent.left
                    anchors.topMargin:   10 * deckView.scale
                    anchors.leftMargin:  10 * deckView.scale
                    width:   screenArea.width - 20 * deckView.scale
                    spacing: Math.round(5 * deckView.scale)

                    Repeater {
                        model: root.tokens.length + 1

                        Rectangle {
                            property bool   filled:   index < root.tokens.length
                            // Map thin arrows → bold filled triangles
                            property string rawTok:   filled ? root.tokens[index] : ""
                            property string dispTok:  rawTok.replace("↑","▲").replace("↓","▼").replace("←","◀").replace("→","▶")

                            height: Math.round(28 * deckView.scale)
                            // Width: text-driven with min/padding so empty box stays square
                            width:  Math.max(
                                        lbl.implicitWidth + Math.round(12 * deckView.scale),
                                        Math.round(28 * deckView.scale))
                            radius: 4 * deckView.scale
                            color:        filled ? "#313244" : "#181825"
                            border.color: filled ? "#89b4fa" : "#313244"
                            border.width: 1

                            Text {
                                id:                  lbl
                                anchors.centerIn:    parent
                                text:                filled ? (root.showTokens ? dispTok : "●") : ""
                                color:               "#cdd6f4"
                                font.pixelSize:      Math.round(11 * deckView.scale)
                                font.family:         "monospace"
                                font.bold:           true
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment:   Text.AlignVCenter
                            }
                        }
                    }
                }

                // ✓ / ✗ status — centred when finishing
                Text {
                    anchors.centerIn:    parent
                    visible:             root.statusText !== ""
                    text:                root.statusText
                    color:               root.statusText === "✓" ? "#a6e3a1" : "#f38ba8"
                    font.pixelSize:      Math.round(48 * deckView.scale)
                    horizontalAlignment: Text.AlignHCenter
                }
            }
        }

        // ── Password input overlay (passwordMode) ─────────────────────────────
        Rectangle {
            anchors.centerIn: parent
            visible:          root.passwordMode && !root.finishing
            width:            420; height: 160
            radius:           12
            color:            "#e61e1e2e"
            border.color:     "#585b70"; border.width: 1

            Column {
                anchors.centerIn: parent
                spacing:          14

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text:           "Enter system password"
                    color:          "#cdd6f4"
                    font.pixelSize: 15
                    font.bold:      true
                }

                // Password field
                Rectangle {
                    width:  340; height: 36
                    anchors.horizontalCenter: parent.horizontalCenter
                    radius: 6
                    color:  "#181825"
                    border.color: pwdField.activeFocus ? "#89b4fa" : "#45475a"
                    border.width: 1

                    TextInput {
                        id:             pwdField
                        anchors.fill:   parent
                        anchors.margins: 10
                        echoMode:       TextInput.Password
                        color:          "#cdd6f4"
                        font.pixelSize: 15
                        font.family:    "monospace"
                        focus:          root.passwordMode && !root.finishing

                        Keys.onReturnPressed: {
                            if (text.length > 0) {
                                client.send_ui_password(text)
                                text = ""
                            }
                        }
                        Keys.onEscapePressed: {
                            client.send_ui_cancel()
                        }
                    }
                }

                // Buttons row
                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 12

                    // Cancel
                    Rectangle {
                        width: 100; height: 32; radius: 6
                        color:        cancelBtn.containsMouse ? "#40f38ba8" : "#201e1e2e"
                        border.color: "#f38ba8"; border.width: 1
                        Text { anchors.centerIn: parent; text: "Cancel"
                               color: "#f38ba8"; font.pixelSize: 13 }
                        MouseArea {
                            id: cancelBtn; anchors.fill: parent; hoverEnabled: true
                            onClicked: client.send_ui_cancel()
                        }
                    }

                    // Confirm
                    Rectangle {
                        width: 100; height: 32; radius: 6
                        color:        confirmBtn.containsMouse ? "#4089b4fa" : "#201e1e2e"
                        border.color: pwdField.text.length > 0 ? "#89b4fa" : "#45475a"
                        border.width: 1
                        Text { anchors.centerIn: parent; text: "Confirm"
                               color: pwdField.text.length > 0 ? "#89b4fa" : "#585b70"
                               font.pixelSize: 13 }
                        MouseArea {
                            id: confirmBtn; anchors.fill: parent; hoverEnabled: true
                            onClicked: {
                                if (pwdField.text.length > 0) {
                                    client.send_ui_password(pwdField.text)
                                    pwdField.text = ""
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ── ButtonGlow inline component ───────────────────────────────────────────
    component ButtonGlow: Item {
        property real   svgX:      0
        property real   svgY:      0
        property real   scale_:    1.0
        property color  glowColor: "#ffffff"
        property string label:     ""

        x:      svgX * scale_ - width  / 2
        y:      svgY * scale_ - height / 2
        width:  Math.round(28 * scale_)
        height: Math.round(28 * scale_)

        Rectangle {
            anchors.centerIn: parent
            width: parent.width * 1.8; height: parent.height * 1.8
            radius: width / 2; color: "transparent"
            border.color: Qt.rgba(glowColor.r, glowColor.g, glowColor.b, 0.35)
            border.width: 2
        }
        Rectangle {
            anchors.fill: parent
            radius: width / 2
            color:        Qt.rgba(glowColor.r, glowColor.g, glowColor.b, 0.25)
            border.color: glowColor; border.width: 1.5
        }
        Text {
            anchors.centerIn: parent
            text: label; color: glowColor
            font.pixelSize: Math.round(9 * scale_); font.bold: true
        }
    }
}
