# TODO

## backup-key

- [ ] **File systems without lock support (some FUSE, SMB, NFS).** If
  `try_lock_exclusive` returns an error (ENOLCK, EOPNOTSUPP), the freshly created
  temp file is left on disk, and stale cleanup skips it as well
  (`crates/cli/src/backup.rs`, `create_locked` and `remove_stale_tmp`). On such a
  file system every run fails and leaves a new orphan. Remove our own just-created
  file in the error branch (after checking dev/ino) and report clearly that the
  file system does not support locking.
- [ ] **O_NOFOLLOW / O_NONBLOCK in stale cleanup.** `remove_stale_tmp` checks the
  type with `symlink_metadata` and then calls `File::open`, which follows symlinks
  and blocks on a FIFO if the name is swapped in between. Open with
  `custom_flags(O_NOFOLLOW | O_NONBLOCK)`. Only someone with write access to the
  same directory can exploit this.
- [ ] **Hung write cannot be interrupted.** Once the main thread has claimed
  publishing, SIGINT/SIGTERM are ignored until the process exits (tokio does not
  restore default signal handling). If `publish`, fsync or the read-back hangs
  (e.g. on NFS), Ctrl+C does nothing and only `kill -9` helps. At least document
  it in the code; ideally restore default handling or use a timeout.
- [ ] **`same_file` on Windows compares only the size.** The non-unix
  `same_file` (`crates/cli/src/backup.rs`) checks `is_file()` and `len()`, so
  `create_locked` and `remove_stale_tmp` cannot tell two different files of the
  same size apart (the unix version compares dev/ino). Compare the volume serial
  number and file index (`GetFileInformationByHandle`) instead.
