use cxx_qt_build::{CxxQtBuilder, QmlModule};

fn main() {
    CxxQtBuilder::new_qml_module(
        QmlModule::new("org.deckery.authui")
            .qml_file("qml/PinDisplay.qml"),
    )
    .qrc("assets/assets.qrc")
    .file("src/display_client.rs")
    .qt_module("Quick")
    .qt_module("Qml")
    .build();
}
