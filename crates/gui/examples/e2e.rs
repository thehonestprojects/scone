//! E2E check of the GUI backend against the live relay + store
//! (127.0.0.1:7474, /tmp/scone-gui-e2e). Run with the relay up.

use gui::backend;

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        match backend::relay_status("127.0.0.1:7474").await {
            Ok(st) => println!(
                "relay_status OK: height={} domains={} peer={}",
                st.height,
                st.domain_count,
                &st.peer_id[..16]
            ),
            Err(e) => {
                println!("relay_status ERR: {e}");
                std::process::exit(1);
            }
        }
        match backend::explore_name("127.0.0.1:7474", "example.uip").await {
            Ok(card) => println!(
                "explore_name OK: name={} registered={} id={}",
                card.name,
                card.registered,
                &card.domain_id[..16]
            ),
            Err(e) => {
                println!("explore_name ERR: {e}");
                std::process::exit(1);
            }
        }
        match backend::relay_status("127.0.0.1:1").await {
            Ok(_) => {
                println!("unreachable relay should fail");
                std::process::exit(1);
            }
            Err(e) => println!(
                "unreachable handled: {}",
                e.to_string().chars().take(60).collect::<String>()
            ),
        }
    });
    // Owner walk against the LIVE (locked) store of the relay.
    match backend::explore_owner(
        Some(std::path::Path::new("/tmp/scone-gui-e2e")),
        &"11".repeat(32),
    ) {
        Ok(p) => println!(
            "explore_owner OK against live store: {} domains",
            p.domains.len()
        ),
        Err(e) => {
            println!("explore_owner ERR: {e}");
            std::process::exit(1);
        }
    }
    println!("E2E-ALL-OK");
}
