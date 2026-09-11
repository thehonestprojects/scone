//! Scone GUI v1 — a single read-only desktop page.
//!
//! Sections (top to bottom):
//! - **Relay**: address input + connect button → status card
//!   (peer id, tip, height, peers, domains, mempool).
//! - **Active identity**: current identity name + OwnerId (selection
//!   from the identity management list; no passphrase handling in
//!   v1 — read-only).
//! - **Explorer**: query by name OR by OwnerId (64 hex). Name →
//!   on-chain state + chain-verified DNS records (through the relay
//!   RPC). OwnerId → owned domains read directly from the relay's
//!   store (read-only redb open).
//! - **Identities**: list of the local keystore, click to make one
//!   active.
//!
//! Nothing here ever writes: no transaction, no store mutation, no
//! key decryption.

pub mod backend;

use backend::{DomainCard, GuiError, IdentityRow, RelayStatus};
use dioxus::prelude::*;
use dioxus_free_icons::Icon;
use dioxus_free_icons::icons::fa_solid_icons::{FaIdCard, FaMagnifyingGlass, FaServer, FaUsers};

/// Binary entry point (the bin crate calls this).
pub fn main_entry() {
    dioxus::launch(App);
}

/// Which explorer mode is active.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum ExploreMode {
    /// Query by domain name.
    #[default]
    Name,
    /// Query by OwnerId (64 hex).
    Owner,
}

/// Everything the page carries.
#[derive(Clone)]
struct PageState {
    relay_addr: String,
    connected: Option<RelayStatus>,
    connect_error: String,
    query: String,
    mode: ExploreMode,
    exploring: bool,
    result: Option<Result<Vec<DomainCard>, String>>,
    identities: Vec<IdentityRow>,
    identities_error: String,
    active: Option<usize>,
}

impl Default for PageState {
    fn default() -> Self {
        Self {
            relay_addr: backend::DEFAULT_RPC_ADDR.into(),
            connected: None,
            connect_error: String::new(),
            query: String::new(),
            mode: ExploreMode::Name,
            exploring: false,
            result: None,
            identities: Vec::new(),
            identities_error: String::new(),
            active: None,
        }
    }
}

#[component]
fn App() -> Element {
    let mut s = use_signal(PageState::default);

    // Initial identities scan (keystore listing, sync + fast).
    use_effect(move || {
        if !s.read().identities_loaded() {
            match backend::list_identities() {
                Ok(list) => s.write().identities = list,
                Err(e) => s.write().identities_error = e.to_string(),
            }
        }
    });

    rsx! {
        document::Stylesheet { href: asset!("/assets/main.css") }
        div { class: "page",
            h1 { class: "title", "Scone — explorateur (lecture seule)" }

            section { class: "card",
                header { class: "card-head",
                    Icon { icon: FaServer }
                    h2 { "Relay" }
                }
                div { class: "row",
                    input {
                        class: "input grow",
                        placeholder: "127.0.0.1:7474",
                        value: "{s().relay_addr}",
                        oninput: move |e| s.write().relay_addr = e.value(),
                    }
                    button {
                        class: "btn",
                        disabled: s().connected.is_some(),
                        onclick: move |_| {
                            let addr = s.read().relay_addr.clone();
                            s.write().connected = None;
                            s.write().connect_error.clear();
                            spawn(async move {
                                match backend::relay_status(&addr).await {
                                    Ok(status) => {
                                        s.write().connected = Some(status);
                                        s.write().connect_error.clear();
                                    }
                                    Err(e) => {
                                        s.write().connect_error = e.to_string();
                                    }
                                }
                            });
                        },
                        "Connecter"
                    }
                }
                if !s().connect_error.is_empty() {
                    p { class: "error", "{s().connect_error}" }
                }
                if let Some(st) = &s().connected {
                    table { class: "kv",
                        tr { td { "peer id" }   td { "{st.peer_id}" } }
                        tr { td { "tip" }       td { "{st.tip}" } }
                        tr { td { "hauteur" }   td { "{st.height}" } }
                        tr { td { "pairs" }     td { "{st.peers}" } }
                        tr { td { "domaines" }  td { "{st.domain_count}" } }
                        tr { td { "mempool" }   td { "{st.mempool}" } }
                    }
                }
            }

            section { class: "card",
                header { class: "card-head",
                    Icon { icon: FaIdCard }
                    h2 { "Identité active" }
                }
                if let Some(id) = s().active.and_then(|i| s().identities.get(i).cloned()) {
                    table { class: "kv",
                        tr { td { "nom" }  td { "{id.name}" } }
                        tr { td { "owner id" }  td { class: "mono", "{owner_display(&id)}" } }
                    }
                } else {
                    p { class: "muted", "aucune — cliquer une identité ci-dessous" }
                }
            }

            section { class: "card",
                header { class: "card-head",
                    Icon { icon: FaMagnifyingGlass }
                    h2 { "Explorateur" }
                }
                div { class: "row",
                    div { class: "tabs",
                        button {
                            class: if s().mode == ExploreMode::Name { "tab active" } else { "tab" },
                            onclick: move |_| s.write().mode = ExploreMode::Name,
                            "Nom"
                        }
                        button {
                            class: if s().mode == ExploreMode::Owner { "tab active" } else { "tab" },
                            onclick: move |_| s.write().mode = ExploreMode::Owner,
                            "OwnerId"
                        }
                    }
                    input {
                        class: "input grow",
                        placeholder: if s().mode == ExploreMode::Name {
                            "example.uip"
                        } else {
                            "64 caractères hex (owner id)"
                        },
                        value: "{s().query}",
                        oninput: move |e| s.write().query = e.value(),
                        onkeydown: move |e| {
                            if e.key() == Key::Enter && !s.read().exploring {
                                start_explore(s);
                            }
                        },
                    }
                    button {
                        class: "btn",
                        disabled: s().exploring,
                        onclick: move |_| start_explore(s),
                        if s().exploring { "…" } else { "Explorer" }
                    }
                }
                ExplorerResult { s }
            }

            section { class: "card",
                header { class: "card-head",
                    Icon { icon: FaUsers }
                    h2 { "Identités" }
                }
                if !s().identities_error.is_empty() {
                    p { class: "error", "{s().identities_error}" }
                } else if s().identities.is_empty() {
                    p { class: "muted", "aucune identité dans ~/.scone/keys" }
                } else {
                    ul { class: "list",
                        for (i, id) in s().identities.iter().enumerate() {
                            li {
                                class: if s().active == Some(i) { "list-row selected" } else { "list-row" },
                                onclick: move |_| s.write().active = Some(i),
                                span { "{id.name}" }
                                span { class: "mono muted", "{owner_display(id)}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// OwnerId shown for an identity, or a hint that it needs v2 unlock.
fn owner_display(id: &IdentityRow) -> String {
    if id.owner_id.is_empty() {
        "(déverrouillage requis — v2)".into()
    } else {
        id.owner_id.clone()
    }
}

/// Launches an exploration (name or owner mode) on a spawned task.
fn start_explore(mut s: Signal<PageState>) {
    let mode = s.read().mode;
    let query = s.read().query.trim().to_string();
    if query.is_empty() {
        return;
    }
    let relay = s.read().relay_addr.clone();
    s.write().exploring = true;
    s.write().result = None;
    spawn(async move {
        let outcome = match mode {
            ExploreMode::Name => backend::explore_name(&relay, &query)
                .await
                .map(|card| vec![card])
                .map_err(err_text),
            ExploreMode::Owner => {
                // Blocking store read: keep it off the render thread.
                let q = query.clone();
                tokio::task::spawn_blocking(move || backend::explore_owner(None, &q))
                    .await
                    .unwrap_or_else(|e| Err(GuiError::Store(e.to_string())))
                    .map(|portfolio| portfolio.domains)
                    .map_err(err_text)
            }
        };
        s.write().exploring = false;
        s.write().result = Some(outcome);
    });
}

impl PageState {
    /// Whether the keystore has been scanned at least once.
    fn identities_loaded(&self) -> bool {
        !(self.identities.is_empty() && self.identities_error.is_empty())
    }
}

/// Result area of the explorer: pending / error / empty / cards.
#[component]
fn ExplorerResult(s: Signal<PageState>) -> Element {
    if s().exploring {
        return rsx! { p { class: "muted", "recherche en cours…" } };
    }
    let Some(result) = s().result.clone() else {
        return rsx! { p { class: "muted", "aucune recherche" } };
    };
    match result {
        Err(msg) => rsx! { p { class: "error", "{msg}" } },
        Ok(cards) if cards.is_empty() => {
            rsx! { p { class: "muted", "aucun domaine trouvé pour cette requête" } }
        }
        Ok(cards) => rsx! {
            for card in cards {
                DomainCardView { key: "{card.domain_id}", card: card.clone() }
            }
        },
    }
}

/// Renders one explored domain (on-chain card + DNS records).
#[component]
fn DomainCardView(card: DomainCard) -> Element {
    rsx! {
        div { class: "domain-card",
            h3 { "{card.name}" }
            table { class: "kv",
                tr { td { "domain id" }   td { class: "mono", "{card.domain_id}" } }
                tr { td { "enregistré" }  td { "{card.registered}" } }
                tr { td { "owner" }       td { class: "mono", "{card.owner}" } }
                tr { td { "séquence" }    td { "{card.sequence}" } }
                tr { td { "record hash" } td { class: "mono", "{card.record_hash}" } }
            }
            if card.dns.is_empty() {
                p { class: "muted", "aucun record DNS vérifié en cache local" }
            } else {
                table { class: "dns",
                    thead { tr { th { "type" } th { "valeur" } } }
                    tbody {
                        for entry in &card.dns {
                            tr { td { "{entry.kind}" } td { "{entry.value}" } }
                        }
                    }
                }
            }
        }
    }
}

/// Normalizes an error to display text.
fn err_text(e: GuiError) -> String {
    e.to_string()
}
