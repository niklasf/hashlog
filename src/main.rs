use std::{fs, fs::File, io::Read, path, path::PathBuf};

use clap::Parser;
use rusqlite::{Connection, OpenFlags, named_params};
use sha1::{Digest, Sha1};

#[derive(clap::Parser, Debug)]
enum Command {
    Add(Add),
}

#[derive(clap::Parser, Debug)]
struct Add {
    files: Vec<PathBuf>,
}

fn main() {
    let opt = Command::parse();

    let conn = init_database();

    match opt {
        Command::Add(add) => do_add(&conn, &add),
    }
}

fn do_add(conn: &Connection, add: &Add) {
    let hostname = hostname::get()
        .expect("hostname")
        .to_str()
        .expect("hostname as str")
        .to_owned();

    let mut buffer = [0; 1 << 14];

    let mut stmt = conn
        .prepare("INSERT INTO hashes (hostname, path, algorithm, hash) VALUES (?, ?, ?, ?)")
        .expect("prepare statement");

    for file in &add.files {
        let abs_path = path::absolute(file)
            .expect("absolute path")
            .to_str()
            .expect("path to string")
            .to_owned();

        let mut reader = File::open(&abs_path).expect("open file");

        let mut md5 = md5::Context::new();
        let mut sha1 = Sha1::new();

        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    md5.consume(&buffer[..n]);
                    sha1.update(&buffer[..n]);
                }
                Err(e) => panic!("Error reading {file:?}: {e}"),
            }
        }

        stmt.execute((&hostname, &abs_path, "md5", &md5.finalize().0))
            .expect("insert md5");
        stmt.execute((&hostname, &abs_path, "sha1", &sha1.finalize()[..]))
            .expect("insert sha1");
    }
}

fn init_database() -> Connection {
    let directory = dirs::data_dir().expect("data dir").join("hashlog");

    fs::create_dir_all(&directory).expect("create directory");

    let conn = Connection::open_with_flags(
        directory.join("hashlog.db"),
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .expect("open database");

    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS hashes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            path TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            hash BLOB NOT NULL,
            hashed_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_hashes_path ON hashes (hostname, path);
        "#,
    )
    .expect("initialize schema");

    conn
}
