//! `deckery-auth-ui` — Layer Shell overlay for controller PIN entry.

mod display_client;

use cxx_qt_lib::{QGuiApplication, QQmlApplicationEngine, QUrl};

fn main() {
    let mut app = QGuiApplication::new();
    let mut engine = QQmlApplicationEngine::new();

    if let Some(engine) = engine.as_mut() {
        engine.load(&QUrl::from("qrc:/qt/qml/org/deckery/authui/qml/PinDisplay.qml"));
    }

    if let Some(app) = app.as_mut() {
        app.exec();
    }
}
