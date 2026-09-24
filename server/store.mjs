import { DatabaseSync } from "node:sqlite";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
export class SessionStore {
  constructor(path) {
    if (path !== ":memory:")
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON;
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, tokenHash TEXT NOT NULL, publicKey TEXT NOT NULL,
        contextMessage TEXT NOT NULL, createdAt INTEGER NOT NULL, expiresAt INTEGER NOT NULL,
        reclaimId TEXT, providerVersion TEXT, status TEXT NOT NULL,
        ownerKey TEXT, ciphertext TEXT
      );
      CREATE TABLE IF NOT EXISTS proof_receipts (
        proofHash TEXT PRIMARY KEY, sessionId TEXT NOT NULL, expiresAt INTEGER NOT NULL
      );`);
    // A process crash during verification never turns an incomplete result into a valid map.
    this.db
      .prepare("UPDATE sessions SET status='pending' WHERE status='verifying'")
      .run();
  }
  create(s) {
    this.db
      .prepare(
        "INSERT INTO sessions (id,tokenHash,publicKey,contextMessage,createdAt,expiresAt,status) VALUES (?,?,?,?,?,?,?)",
      )
      .run(
        s.id,
        s.tokenHash,
        JSON.stringify(s.publicKey),
        s.contextMessage,
        s.createdAt,
        s.expiresAt,
        "initializing",
      );
  }
  configure(id, reclaimId, version) {
    this.db
      .prepare(
        "UPDATE sessions SET reclaimId=?,providerVersion=?,status='pending' WHERE id=? AND status='initializing'",
      )
      .run(reclaimId, version, id);
  }
  get(id) {
    const r = this.db.prepare("SELECT * FROM sessions WHERE id=?").get(id);
    return r
      ? {
          ...r,
          publicKey: JSON.parse(r.publicKey),
          ciphertext: r.ciphertext ? JSON.parse(r.ciphertext) : null,
        }
      : null;
  }
  acquire(id) {
    return (
      this.db
        .prepare(
          "UPDATE sessions SET status='verifying' WHERE id=? AND status='pending'",
        )
        .run(id).changes === 1
    );
  }
  release(id) {
    this.db
      .prepare(
        "UPDATE sessions SET status='pending' WHERE id=? AND status='verifying'",
      )
      .run(id);
  }
  complete(id, owner, payload, hashes, expiresAt) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const hash of hashes)
        this.db
          .prepare("INSERT INTO proof_receipts VALUES(?,?,?)")
          .run(hash, id, expiresAt);
      const changed = this.db
        .prepare(
          "UPDATE sessions SET ownerKey=?,ciphertext=?,status='ready',expiresAt=? WHERE id=? AND status='verifying'",
        )
        .run(owner, JSON.stringify(payload), expiresAt, id).changes;
      if (changed !== 1) throw new Error("Session changed");
      this.db.exec("COMMIT");
    } catch {
      this.db.exec("ROLLBACK");
      throw new Error("Result rejected");
    }
  }
  remove(id) {
    this.db.prepare("DELETE FROM sessions WHERE id=?").run(id);
  }
  prune(now) {
    this.db.prepare("DELETE FROM sessions WHERE expiresAt<?").run(now);
    this.db.prepare("DELETE FROM proof_receipts WHERE expiresAt<?").run(now);
  }
  count() {
    return this.db.prepare("SELECT COUNT(*) n FROM sessions").get().n;
  }
  close() {
    this.db.close();
  }
}
