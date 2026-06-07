---
title: "Building an EASM in Rust: Bypassing SQLite Concurrent Locks with RAM Aggregation"
date: "2026-06-07"
draft: false
tags: ["rust", "sqlite", "easm", "tokio", "architecture"]
ShowToc: true
TocOpen: false
---

# Building an EASM in Rust: Bypassing SQLite Concurrent Locks with RAM Aggregation

As I wrap up my undergraduate computer science engineering degree, I’ve been researching how organizations monitor their network perimeter. The External Attack Surface Management (EASM) market is dominated by massive platforms built for the enterprise. They are incredibly powerful, but for Small and Medium Businesses (SMBs) or IT agencies managing a handful of `/24` subnets, these tools are prohibitively expensive and overly complex.

I wanted to build an "EASM Lite" - a set-and-forget daemon that scans an organization's perimeter, diffs the state against previous scans, and alerts them via Webhooks or Email when a new port opens, a certificate is about to expire, or a rogue Subject Alternative Name (SAN) appears.

Here is how I architected the core engine in Rust, and the specific database trade-offs I made to keep it lightweight.

---

## 1. The Engine: LYNX & The Differ

To power the actual network discovery, I used a custom TLS/Port scanner I previously built called **LYNX**. Built on Rust’s `tokio` asynchronous runtime, it handles highly concurrent network I/O to scan CIDR blocks much faster than traditional sequential tools. It aggressively pulls TLS certificates, parses their SHA-256 fingerprints, SANs, and `not_after` expiration dates.

However, scanning is only half the battle. An EASM is fundamentally a state machine. It requires persistent storage to compare today's network state against last week's network state. 

I wrote a core diffing engine (`asm-core`) that loads the previous snapshot and the current snapshot, performing a deep comparison to emit structured `DiffEvent` records:
- `cert_changed`: A fingerprint rotation occurred.
- `new_san`: A developer expanded a certificate (e.g., adding `staging.example.com` to an existing cert).
- `cert_expiring`: A Critical alert fired when `not_after` drops below 30 days.

For an SMB tool intended to be self-hosted on a cheap VPS or a Raspberry Pi, **SQLite** via the `sqlx` crate was the obvious choice for storing these snapshots.

---

## 2. The Dilemma: Tokio vs. SQLite

Combining highly concurrent Tokio tasks with SQLite creates an immediate bottleneck. SQLite handles reads beautifully, but it is notoriously unforgiving with highly concurrent write access. 

Initially, the architecture looked like this: as Tokio workers discovered open ports or parsed TLS certificates, they funneled those results through an MPSC (Multi-Producer, Single-Consumer) channel to a dedicated database writer thread. 

Under heavy CIDR scanning load, this approach failed. The cross-thread synchronization added CPU latency, and funneling thousands of state changes sequentially into SQLite eventually triggered `database is locked (8)` panics. Even with Write-Ahead Logging (WAL) enabled, the sheer volume of rapid-fire atomic inserts from the consumer thread choked the database.

---

## 3. The Solution: Decoupling I/O from Storage

To bypass the concurrent write-lock issue entirely, I decided to aggressively decouple the network phase from the storage phase.

Instead of writing to the database dynamically as discoveries are made, the Tokio workers never touch SQLite. Instead:

1. **Memory Aggregation:** The async tasks build a single, aggregated `ScanResult` struct entirely in RAM.
2. **Uninhibited I/O:** The network phase (`lynx::Scanner::run`) runs to 100% completion without ever waiting on a disk write.
3. **Batch Insertion:** Back in the main execution thread, a single SQLite transaction is opened (`db.begin()`). The engine sequentially loops through the aggregated in-memory `ScanResult` and performs a massive bulk-insert before committing the transaction (`tx.commit()`).

---

## 4. The Trade-offs (Where I need your thoughts)

This architectural choice provides a massive reliability win: **Atomicity**. Because the SQLite inserts happen in a single SQL transaction at the very end, a process crash or sudden termination mid-scan guarantees that no corrupted or partial scan data pollutes the database. It is either a 100% successful scan, or it doesn't log at all. There is zero lock contention because there is only one writer.

But this design carries a fatal flaw at scale: **The OOM Trap**.

This RAM-aggregation strategy works flawlessly for its target market-SMBs scanning `/24` subnets or a dozen top-level domains. However, if I were to point this tool at an enterprise `/8` block, holding millions of port states and certificate chains in RAM simultaneously would cause the host OS to OOM-kill the Rust process before the SQLite transaction ever begins.

To scale this to an enterprise level, the architecture would need to pivot back to a streaming model, likely dropping SQLite entirely in favor of chunked batch-inserts into **PostgreSQL** or **ClickHouse** with active connection pooling.

For now, the SQLite/RAM approach solves the immediate SMB use case perfectly. But before I start building out the commercial multi-tenant web dashboard on top of this engine, I'm looking for feedback from the systems engineering community:

> 1. Are there hidden memory leaks in this RAM-aggregation approach for long-running Rust daemons using `tokio-cron-scheduler`?
> 2. How would you have handled the SQLite concurrency differently without upgrading to Postgres? Would chunked MPSC inserts with manual `BEGIN`/`COMMIT` intervals have solved the lock contention?

---

*If you're curious about the underlying network architecture powering this, I wrote a deep-dive article detailing how the LYNX scanner achieves its high concurrency:*
**[Read the LYNX Engine Architecture Deep-Dive Here](https://syed-anwar-uddin.github.io/posts/lynx-unified-bandwidth-governance/)**
