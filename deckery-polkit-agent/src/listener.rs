//! polkit Listener implementation — receives `BeginAuthentication` calls from
//! polkitd and forwards them to the iced event loop via an mpsc channel.

pub use crate::Message;
use futures::channel::mpsc::Sender;
use glib::object::Cast;
use glib::subclass::prelude::*;
use polkit_agent_rs::Listener;
use polkit_agent_rs::gio;
use polkit_agent_rs::polkit;
use polkit_agent_rs::polkit::UnixUser;
use polkit_agent_rs::subclass::ListenerImpl;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct DeckeryListenerImpl {
    pub sender: Arc<Mutex<Option<Sender<Message>>>>,
}

#[glib::object_subclass]
impl ObjectSubclass for DeckeryListenerImpl {
    const NAME: &'static str = "DeckeryListener";
    type Type = DeckeryListener;
    type ParentType = Listener;
}

impl ObjectImpl for DeckeryListenerImpl {}

glib::wrapper! {
    pub struct DeckeryListener(ObjectSubclass<DeckeryListenerImpl>)
        @extends Listener;
}

impl ListenerImpl for DeckeryListenerImpl {
    type Message = String;

    fn initiate_authentication(
        &self,
        _action_id: &str,
        message: &str,
        icon_name: &str,
        _details: &polkit::Details,
        cookie: &str,
        identities: Vec<polkit::Identity>,
        _cancellable: gio::Cancellable,
        task: gio::Task<Self::Message>,
    ) {
        let users: Vec<UnixUser> = identities
            .into_iter()
            .flat_map(|id| id.dynamic_cast())
            .collect();

        if let Ok(mut guard) = self.sender.lock() {
            if let Some(sender) = guard.as_mut() {
                let _ = sender.try_send(Message::NewSession(
                    cookie.to_string(),
                    users
                        .iter()
                        .map(|u| u.name().unwrap().to_string())
                        .collect(),
                    task,
                    message.to_string(),
                    icon_name.to_string(),
                ));
            }
        }
    }

    fn initiate_authentication_finish(
        &self,
        gio_result: Result<gio::Task<Self::Message>, glib::Error>,
    ) -> bool {
        gio_result.is_ok()
    }
}

impl DeckeryListener {
    pub fn new(sender: Arc<Mutex<Sender<Message>>>) -> Self {
        let obj: Self = glib::Object::new();
        let imp = obj.imp();
        *imp.sender.lock().unwrap() = Some(sender.lock().unwrap().clone());
        obj
    }
}
