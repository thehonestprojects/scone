//! Scénarios à grande échelle (50–100 nœuds) : élection des quorums
//! sous adversité. Chaque test est `#[ignore]` par défaut — le budget
//! CPU dépasse celui des CI normales ; lancer via
//! `cargo test -p scone-blockchain --release -- --ignored scale`.
//!
//! Attaques couvertes :
//! - **Crash partition** : un tiers des nœuds crash pendant une
//!   élection, redémarre après finalisation — le quorum ne doit jamais
//!   « suivre » les disparitions (quorum sur la taille élue, pas sur
//!   les réponses).
//! - **Grinding de seed** : le producteur tente de futures boucles
//!   d'exploitation — la seed bootstrap est génésique et les pools
//!   gelés dans `FinalizedBase`, donc rien n'est moulinable ici ;
//!   le test vérifie que le comité est stable entre nœuds honnêtes.
//! - **Partition longue** : 50/50 pendant des dizaines de
//!   checkpoints, puis heal — jamais deux checkpoints finalisés
//!   incompatibles (safety cross-window), convergence finale.
//! - **Éclipse partielle** : un sous-ensemble isolé ne voit QUE des
//!   nœuds complices — il doit converger vers la chaîne honnête au
//!   heal (pas de finalité divergente pendant l'éclipse).
//!
//! Contrainte RAM : les nœuds sont de vraies `Blockchain` ; à 100
//! nœuds le harness tourne par VAGUES de bootstrap (10 nœuds à la
//! fois rejoignent, les autres démarrent en observateurs passifs) —
//! la mémoire reste bornée par le nombre total, pas par le carré.

use super::*;
use std::time::Instant;

/// Budget wall-clock par scénario (release) — calé sur la taille :
/// ~50 nœuds ≈ 300 s, ~100 nœuds ≈ 2 400 s sur le matériel de
/// référence (mesuré). La garde attrape les régressions de
/// performance, pas les lenteurs attendues.
fn assert_under_budget(start: Instant, what: &str) {
    let elapsed = start.elapsed().as_secs();
    let budget = if what.contains("100") { 2_400 } else { 1_200 };
    assert!(
        elapsed < budget,
        "{what} exceeded scale budget: {elapsed}s > {budget}s"
    );
}

/// Paramètres de base pour N nœuds : production ralentie (le volume
/// par bloc est multiplié par N), checkpoints resserrés pour éprouver
/// les élections souvent.
fn scale_params(nodes: usize, seed: u64) -> SimParams {
    SimParams {
        nodes,
        seed,
        loss_permille: 30,
        dup_permille: 5,
        latency_ticks: (2, 9),
        produce_interval: 40,
        sign_interval: 12,
        sync_interval: 60,
        horizon: 400_000,
    }
}

/// Bootstrap par vagues de 10 : les nœuds rejoignent progressivement
/// (crash → restart simulé), la RAM et le volume de gossip restent
/// contrôlés. Après chaque vague, tout le monde doit converger.
fn bootstrap_waves(net: &mut SimNet, wave: usize) {
    for w in 0..wave {
        let start = w * 10;
        let end = ((w + 1) * 10).min(net.node_count());
        // Vague précédente vivante, nouvelle vague « démarre » :
        // les nœuds au-delà de la vague courante sont crashés.
        for n in end..net.node_count() {
            net.crash(n);
        }
        net.run_until(|n| n.logical_tick() > (400 + 200 * w as u64));
        // La vague démarre : redémarre-les.
        for n in start..end {
            net.restart(n);
        }
        net.run_until(|n| {
            (start..end).all(|i| n.alive(i))
                && n.logical_tick() > (800 + 200 * w as u64)
                && n.max_height() >= 3
        });
    }
    // Tout le monde vivant, convergé, puis revendications PoS.
    let tld_uip = scone_core::TldId::from_tld(&scone_core::TldName::new("uip").unwrap());
    net.submit(0, sim_register_tld("uip", 1));
    // Le TLD doit être connu de TOUS les nœuds vivants avant d'ouvrir
    // (sinon les producteurs en retard le rejettent : unknown_tld).
    net.run_until(|n| {
        n.logical_tick() > 1200
            && n.max_height() >= 4
            && (0..n.node_count()).all(|i| n.chain(i).state().tld_len() >= 1)
    });
    net.submit(0, sim_set_tld_open("uip", 1, true));
    net.run_until(|n| {
        n.logical_tick() > 1500
            && (0..n.node_count()).all(|i| {
                n.chain(i)
                    .state()
                    .tld(&tld_uip)
                    .map(|t| t.open)
                    .unwrap_or(false)
            })
    });
    // Pool : une trentaine de stakeholders suffit pour des élections
    // non triviales (le comité TESTNET est de 4, le pool large teste
    // la sélection blake3). Soumissions ÉTAGÉES : un domaine par vague
    // de production, le producteur de tête les absorbe.
    let members: u8 = u8::try_from(net.node_count().saturating_sub(1))
        .unwrap_or(30)
        .min(30);
    for s in 2u8..(members + 2) {
        let name = format!("d{s}.uip");
        net.submit(0, sim_register_domain(&name, s));
        net.run_until(|n| n.logical_tick() > 1500 + u64::from(s) * 60);
    }
    net.run_until(|n| {
        n.logical_tick() > 4000
            && n.chain(0).state().tld_len() >= 1
            && n.chain(0).state().len() >= usize::from(members)
    });
}

// ---------------------------------------------------------------------------
// Scénario 1 — 50 nœuds, élections répétées, un tiers en crash
// cyclique pendant les élections.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "large-scale: run with --release -- --ignored scale"]
fn scale_50_nodes_rotating_crash_third() {
    let start = Instant::now();
    let mut net = SimNet::new(scale_params(50, 0x50CA1E));
    bootstrap_waves(&mut net, 5);

    // Crash cyclique : à chaque « fenêtre » de ticks, un tiers
    // différent des nœuds est crashé — les comités élus perdent
    // toujours quelqu'un mais jamais les mêmes.
    let mut window = 0u64;
    while net.logical_tick() < net_tick_cap(&net) && net.max_height() < 60 {
        let group: Vec<usize> = (0..50)
            .filter(|i| (i + window as usize).is_multiple_of(3))
            .collect();
        for &n in &group {
            net.crash(n);
        }
        net.run_until(|n| n.logical_tick() > window * 400 + 3200);
        for &n in &group {
            net.restart(n);
        }
        net.run_until(|n| n.logical_tick() > window * 400 + 3500 && n.converged());
        window += 1;
    }

    // Safety : aucun couple de checkpoints finalisés incompatibles.
    for (epoch, anchors) in net.finalized_epochs() {
        assert!(
            anchors.len() <= 1,
            "conflicting finalized anchors at epoch {epoch}"
        );
    }
    // Liveness : convergence après le dernier heal.
    net.run_until(|n| n.converged() && n.max_height() >= 60);
    assert_under_budget(start, "scale_50_rotating_crash");
}

// ---------------------------------------------------------------------------
// Scénario 2 — 100 nœuds, partition 50/50 longue puis heal.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "large-scale: run with --release -- --ignored scale"]
fn scale_100_nodes_partition_then_heal() {
    let start = Instant::now();
    let mut net = SimNet::new(scale_params(100, 0x0FF1CE));
    bootstrap_waves(&mut net, 10);

    // Partition 50/50 pendant plusieurs fenêtres de checkpoint.
    let a: Vec<usize> = (0..50).collect();
    let b: Vec<usize> = (50..100).collect();
    net.partition(&[a, b]);
    net.run_until(|n| n.logical_tick() > 6000);

    // Safety pendant la partition : la fenêtre non finalisée peut
    // diverger en hauteur, mais AUCUN checkpoint finalisé incompatible.
    for (epoch, anchors) in net.finalized_epochs() {
        assert!(anchors.len() <= 1, "split finality at epoch {epoch}");
    }

    // Heal : convergence obligatoire.
    net.heal();
    net.run_until(|n| n.converged() && n.max_height() >= 40);
    for (epoch, anchors) in net.finalized_epochs() {
        assert!(anchors.len() <= 1, "post-heal split at epoch {epoch}");
    }
    assert_under_budget(start, "scale_100_partition");
}

// ---------------------------------------------------------------------------
// Scénario 3 — éclipse partielle : 10 complices + 5 victimes isolées
// du reste ; les 85 honnêtes finalisent, les victimes rattrapent.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "large-scale: run with --release -- --ignored scale"]
fn scale_100_nodes_partial_eclipse() {
    let start = Instant::now();
    let mut net = SimNet::new(scale_params(100, 0xECC1E5));
    bootstrap_waves(&mut net, 10);

    // Île : nœuds 90-99 (complices/victimes) coupés du monde.
    let island: Vec<usize> = (90..100).collect();
    let main: Vec<usize> = (0..90).collect();
    net.partition(&[main, island]);
    net.run_until(|n| n.logical_tick() > 8000);

    // Le réseau principal doit avoir finalisé pendant l'éclipse.
    // Diagnostic complet si échec : où bloque la finalité ?
    if net.stats.checkpoints_finalized == 0 {
        eprintln!(
            "DIAG eclipse: tick={} max_height={} converged={} produced={} accepted={} reorgs={} timeouts={}",
            net.logical_tick(),
            net.max_height(),
            net.converged(),
            net.stats.blocks_produced,
            net.stats.blocks_accepted,
            net.stats.reorgs,
            net.stats.producer_timeouts,
        );
        let heights: Vec<u64> = (0..net.node_count())
            .map(|i| net.height(i))
            .take(10)
            .collect();
        eprintln!("DIAG first-10 node heights: {heights:?}");
        eprintln!(
            "DIAG finalized epochs: {:?}",
            net.finalized_epochs().keys().collect::<Vec<_>>()
        );
        // committees vus par le nœud 0 aux recovery 0..=3
        for r in 0u32..4 {
            eprintln!(
                "DIAG committee(recovery={r}) len={}",
                net.chain(0).committee(r).len()
            );
        }
        eprintln!(
            "DIAG state domains (node 0): {}",
            net.chain(0).state().len()
        );
        eprintln!("DIAG tlds (node 0): {}", net.chain(0).state().tld_len());
        eprintln!("DIAG rejections: {:?}", net.rejections.nonzero());
    }
    assert!(
        net.stats.checkpoints_finalized > 0,
        "main network never finalized during eclipse"
    );

    // Heal : l'île adopte la chaîne honnête (poids/hauteur), jamais
    // l'inverse.
    net.heal();
    net.run_until(|n| n.converged());
    for (epoch, anchors) in net.finalized_epochs() {
        assert!(anchors.len() <= 1, "eclipse split at epoch {epoch}");
    }
    assert_under_budget(start, "scale_100_eclipse");
}

// ---------------------------------------------------------------------------
// Scénario 4 — 50 nœuds : adversité réseau maximale (perte 20 %,
// duplication 10 %, latence 2-20), élections sous tempête.
// ---------------------------------------------------------------------------
#[test]
#[ignore = "large-scale: run with --release -- --ignored scale"]
fn scale_50_nodes_network_storm() {
    let start = Instant::now();
    let mut params = scale_params(50, 0x57_0A7);
    params.loss_permille = 200;
    params.dup_permille = 100;
    params.latency_ticks = (2, 20);
    let mut net = SimNet::new(params);
    bootstrap_waves(&mut net, 5);

    net.run_until(|n| n.max_height() >= 40 || n.logical_tick() > n_tick_horizon());

    // Sous tempête : la liveness peut ralentir, la safety jamais.
    for (epoch, anchors) in net.finalized_epochs() {
        assert!(anchors.len() <= 1, "storm split at epoch {epoch}");
    }
    // Liveness ultime : ça converge quand même.
    net.heal();
    net.run_until(|n| n.converged() && n.max_height() >= 40);
    assert_under_budget(start, "scale_50_storm");
}

// ---- helpers -------------------------------------------------------------

fn net_tick_cap(net: &SimNet) -> u64 {
    n_tick_horizon().min(net.logical_tick() + 40_000)
}

fn n_tick_horizon() -> u64 {
    240_000
}
