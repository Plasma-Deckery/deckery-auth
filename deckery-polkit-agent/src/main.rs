//! `deckery-polkit-agent` — polkit authentication agent for Deckery.
//!
//! Replaces the Plasma built-in polkit agent. Shows a Layer Shell popup
//! when an application requests authorization via polkit. Supports:
//!   - Password authentication via pam_unix.so (keyboard / virtual keyboard)
//!   - PIN authentication via pam_deckery.so (controller button combos — Step 3)
//!
//! Registers with polkitd at startup via polkit-agent-rs (libpolkit-agent-1).
//! Uses iced_layershell for the Wayland Layer Shell surface.
//!
//! Based on manthanabc/polkit-agent (MIT License).
//! See: https://github.com/Plasma-Deckery/deckery-auth/issues/6

use iced::window::Id;
use iced::{Element, Event, Task as Command, event};
use iced_runtime::window::Action as WindowAction;
use iced_runtime::{Action, task};

use iced_layershell::build_pattern::{MainSettings, daemon};
use iced_layershell::reexport::{Anchor, Layer, NewLayerShellSettings};
use iced_layershell::settings::{LayerShellSettings, StartMode};
use iced_layershell::to_layer_message;
use polkit_agent_rs::polkit::UnixUser;
use std::collections::BTreeMap;

use futures::channel::mpsc::Sender;
use iced::widget::{Space, button, column, pick_list, row, text, text_input};
use iced::{Bottom, Center, Fill};
use polkit_agent_rs::RegisterFlags;
use polkit_agent_rs::Session as AgentSession;
use polkit_agent_rs::gio;
use polkit_agent_rs::polkit::UnixSession;
use polkit_agent_rs::traits::ListenerExt;
use std::sync::Arc;
use std::sync::Mutex;

mod listener;
use listener::DeckeryListener;

const OBJECT_PATH: &str = "/org/deckery/PolicyKit1/AuthenticationAgent";

/// Initiate a PAM authentication session for the given user and cookie.
/// Responds to any PAM_PROMPT_ECHO_OFF or PAM_PROMPT_ECHO_ON prompt with
/// the provided credential (password or PIN string).
fn start_session(
    username: String,
    cookie: String,
    credential: String,
    task: gio::Task<String>,
    window_id: Id,
    sender: Arc<Mutex<Sender<Message>>>,
) {
    let user: UnixUser = UnixUser::new_for_name(&username).unwrap();
    let session = AgentSession::new(&user, &cookie);
    let sub_loop = glib::MainLoop::new(None, true);

    let sub_loop_2 = sub_loop.clone();
    let sender_clone = sender.clone();

    session.connect_completed(move |session, success| {
        unsafe {
            if success {
                task.clone().return_result(Ok("success".to_string()));
                let _ = sender_clone
                    .lock()
                    .unwrap()
                    .try_send(Message::AuthenticationSuccess(window_id));
            } else {
                task.clone().return_result(Err(glib::Error::new(
                    glib::FileError::Failed,
                    "Authentication failed",
                )));
                let _ = sender_clone
                    .lock()
                    .unwrap()
                    .try_send(Message::AuthenticationFailed(
                        window_id,
                        "Authentication failed".to_string(),
                    ));
            }
        }
        session.cancel();
        sub_loop_2.quit();
    });

    session.connect_show_info(|_session, info| {
        println!("[polkit-agent] info: {info}");
    });

    session.connect_show_error(|_session, error| {
        eprintln!("[polkit-agent] error: {error}");
    });

    // Respond to any PAM prompt that expects hidden or visible input —
    // pam_deckery.so sends "Deckery PIN: ", pam_unix.so sends "Password: ".
    // We respond to both without checking the prompt string, so this works
    // regardless of which module runs first in the polkit-1 PAM stack.
    session.connect_request(move |session, _request, _echo_on| {
        session.response(&credential);
    });

    session.initiate();
    sub_loop.run();
}

pub fn main() -> Result<(), iced_layershell::Error> {
    daemon(
        DeckeryPolkitApp::namespace,
        DeckeryPolkitApp::update,
        DeckeryPolkitApp::view,
        DeckeryPolkitApp::remove_id,
    )
    .subscription(DeckeryPolkitApp::subscription)
    .settings(MainSettings {
        layer_settings: LayerShellSettings {
            start_mode: StartMode::Background,
            ..Default::default()
        },
        ..Default::default()
    })
    .run_with(DeckeryPolkitApp::new)
}

#[derive(Debug, Clone)]
struct AuthSession {
    users: Vec<String>,
    selected_user: String,
    cookie: String,
    /// The credential currently typed into the input field (password or PIN).
    credential: String,
    error: Option<String>,
    task: gio::Task<String>,
    /// The message polkit sent (e.g. "Authentication is required to…").
    message: String,
    in_progress: bool,
}

#[derive(Debug, Default)]
struct DeckeryPolkitApp {
    sessions: BTreeMap<iced::window::Id, AuthSession>,
    sender: Option<Arc<Mutex<Sender<Message>>>>,
}

#[to_layer_message(multi)]
#[derive(Debug, Clone)]
pub enum Message {
    WindowClosed(iced::window::Id),
    UserSelected(Id, String),
    CredentialChanged(Id, String),
    Authenticate(Id),
    Cancel(Id),
    NewSession(String, Vec<String>, gio::Task<String>, String, String),
    Close(Id),
    AuthenticationSuccess(Id),
    /// Payload: (window_id, error_message). Allows retry — does not lock the UI.
    AuthenticationFailed(Id, String),
    IcedEvent(Event),
    SetSender(Arc<Mutex<Sender<Message>>>),
}

impl DeckeryPolkitApp {
    fn remove_id(&mut self, id: iced::window::Id) {
        self.sessions.remove(&id);
    }
}

impl DeckeryPolkitApp {
    fn new() -> (Self, Command<Message>) {
        (
            Self {
                sessions: BTreeMap::new(),
                sender: None,
            },
            Command::none(),
        )
    }

    fn namespace(&self) -> String {
        String::from("deckery-polkit-agent")
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch(vec![
            iced::Subscription::run(|| {
                iced::stream::channel(100, |sender| {
                    let sender = Arc::new(Mutex::new(sender));
                    let sender_clone = sender.clone();

                    std::thread::spawn(move || {
                        let main_loop = glib::MainLoop::new(None, true);

                        let listener = DeckeryListener::new(sender);

                        let Ok(subject) = UnixSession::new_for_process_sync(
                            nix::unistd::getpid().as_raw(),
                            gio::Cancellable::NONE,
                        ) else {
                            eprintln!("[polkit-agent] failed to get session subject");
                            return;
                        };

                        let Ok(_handle) = listener.register(
                            RegisterFlags::NONE,
                            &subject,
                            OBJECT_PATH,
                            gio::Cancellable::NONE,
                        ) else {
                            eprintln!("[polkit-agent] failed to register with polkitd — is another agent running?");
                            return;
                        };

                        eprintln!("[polkit-agent] registered with polkitd");
                        main_loop.run();
                    });

                    async move {
                        let _ = sender_clone
                            .lock()
                            .unwrap()
                            .try_send(Message::SetSender(sender_clone.clone()));
                        futures::future::pending::<()>().await;
                    }
                })
            }),
            iced::window::close_events().map(Message::WindowClosed),
            event::listen().map(Message::IcedEvent),
        ])
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::IcedEvent(event) => {
                if let Event::Keyboard(iced::keyboard::Event::KeyPressed {
                    key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape),
                    ..
                }) = event
                {
                    if let Some(id) = self.sessions.keys().next().cloned() {
                        return Command::perform(async move { id }, Message::Cancel);
                    }
                }
                Command::none()
            }

            Message::NewSession(cookie, users, task, message, _icon) => {
                let id = iced::window::Id::unique();
                let selected_user = users.first().cloned().unwrap_or_else(|| "root".to_string());
                self.sessions.insert(
                    id,
                    AuthSession {
                        users,
                        selected_user,
                        cookie,
                        credential: String::new(),
                        error: None,
                        task,
                        message,
                        in_progress: false,
                    },
                );

                Command::perform(async {}, move |_| Message::NewLayerShell {
                    settings: NewLayerShellSettings {
                        size: Some((600, 280)),
                        anchor: Anchor::Right | Anchor::Top | Anchor::Left | Anchor::Bottom,
                        layer: Layer::Overlay,
                        use_last_output: false,
                        ..Default::default()
                    },
                    id,
                })
            }

            Message::UserSelected(id, user) => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.selected_user = user;
                }
                Command::none()
            }

            Message::CredentialChanged(id, value) => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.credential = value;
                }
                Command::none()
            }

            Message::Authenticate(id) => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    if session.in_progress {
                        return Command::none();
                    }
                    session.error = None;
                    session.in_progress = true;

                    let username = session.selected_user.clone();
                    let cookie = session.cookie.clone();
                    let credential = session.credential.clone();
                    let task = session.task.clone();

                    if let Some(sender) = self.sender.clone() {
                        std::thread::spawn(move || {
                            start_session(username, cookie, credential, task, id, sender);
                        });
                    }
                }
                Command::none()
            }

            Message::AuthenticationSuccess(id) => {
                task::effect(Action::Window(WindowAction::Close(id)))
            }

            // On failure: clear credential, show error, allow retry.
            Message::AuthenticationFailed(id, error) => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.error = Some(error);
                    session.in_progress = false;
                    session.credential = String::new();
                }
                Command::none()
            }

            Message::Cancel(id) | Message::Close(id) => {
                task::effect(Action::Window(WindowAction::Close(id)))
            }

            Message::SetSender(sender) => {
                self.sender = Some(sender);
                Command::none()
            }

            _ => Command::none(),
        }
    }

    fn view(&self, id: iced::window::Id) -> Element<Message> {
        let Some(session) = self.sessions.get(&id) else {
            return Space::with_height(0).into();
        };

        let user_picker = pick_list(
            session.users.clone(),
            Some(session.selected_user.clone()),
            move |s| Message::UserSelected(id, s),
        );

        let mut credential_input = text_input("Password or PIN", &session.credential)
            .secure(true)
            .style(|theme, status| {
                let mut style = iced::widget::text_input::default(theme, status);
                style.border.radius = iced::border::radius(8.0);
                style
            })
            .on_input(move |s| Message::CredentialChanged(id, s))
            .padding(10);

        if !session.in_progress {
            credential_input = credential_input.on_submit(Message::Authenticate(id));
        }

        let mut content = column![
            column![
                text(&session.message).size(20),
                column![
                    row![
                        text("Authenticating as:").size(16),
                        user_picker.text_size(16),
                    ]
                    .spacing(5)
                    .align_y(Center),
                    credential_input,
                ]
                .spacing(10),
            ]
            .spacing(20)
            .padding(25),
        ];

        if let Some(error) = &session.error {
            content = content.push(
                text(format!("Authentication failed: {error}"))
                    .size(14)
                    .color(iced::Color::from_rgb(0.8, 0.0, 0.0))
                    .center()
                    .width(Fill),
            );
        }

        let mut cancel_btn =
            button(column![text("Cancel")].width(Fill).align_x(Center)).padding(13);
        if !session.in_progress {
            cancel_btn = cancel_btn.on_press(Message::Cancel(id));
        }

        let mut auth_btn =
            button(column![text("Authenticate")].width(Fill).align_x(Center)).padding(13);
        if !session.in_progress {
            auth_btn = auth_btn.on_press(Message::Authenticate(id));
        }

        content = content.push(Space::with_height(Fill)).push(
            row![cancel_btn, auth_btn]
                .spacing(2)
                .width(Fill)
                .align_y(Bottom),
        );

        content.padding(1).height(Fill).into()
    }
}
