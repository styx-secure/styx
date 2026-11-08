// Experimental Node reference implementation of the M3-RECEIVE receive-state
// port: atomic snapshot files (owner technical gate G1 of M3-RECEIVE-2).
//
// One authoritative file, `receive-state.snapshot`, in a directory owned by
// the caller. A rewrite creates a fresh temporary file in the same directory
// (exclusive create, mode 0600, no symbolic link followed), writes the whole
// encrypted snapshot, fsyncs and closes it, renames it over the
// authoritative name and fsyncs the directory; only then is the write
// reported. Each step is a named point at which a test hook may stop the
// process. A temporary file is never read as state: it is removed when the
// archive is opened. There is no journal and no fallback to an older copy.
import { constants as FS } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const SNAPSHOT_NAME = 'receive-state.snapshot';
export const TEMP_PREFIX = 'receive-state.tmp-';

/** The named steps of one rewrite, in order (kill points of the crash suite). */
export const WRITE_STEPS = Object.freeze([
  'temp-create', 'temp-write', 'temp-fsync', 'temp-close', 'rename', 'directory-fsync', 'reported',
]);

/** A failure whose outcome on disk is unknown (after the rename was attempted). */
export class UncertainWriteError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'UncertainWriteError';
  }
}

/** The file-system part of the archive is not usable (missing, wrong type, symbolic link). */
export class ArchiveLayoutError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = 'ArchiveLayoutError';
  }
}

async function fsyncDirectory(directory) {
  const handle = await open(directory, FS.O_RDONLY | FS.O_DIRECTORY | FS.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function requireDirectory(directory) {
  let info;
  try {
    info = await lstat(directory);
  } catch (error) {
    throw new ArchiveLayoutError('the archive directory is missing', { cause: error });
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw new ArchiveLayoutError('the archive path is not a plain directory');
}

/**
 * Create the archive directory for a new archive (mode 0700) and make its
 * entry durable. Fails if it exists and is not an empty plain directory or
 * already holds a snapshot.
 */
export async function createDirectory(directory, parent) {
  await mkdir(directory, { mode: 0o700, recursive: false }).catch(async (error) => {
    if (error.code !== 'EEXIST') throw error;
  });
  await requireDirectory(directory);
  const names = await readdir(directory);
  if (names.includes(SNAPSHOT_NAME)) throw new ArchiveLayoutError('an archive already exists in this directory');
  await fsyncDirectory(parent);
  await fsyncDirectory(directory);
}

/** Remove orphan temporary files left by an interrupted rewrite (never read as state). */
export async function removeOrphans(directory) {
  await requireDirectory(directory);
  const removed = [];
  for (const name of await readdir(directory)) {
    if (name.startsWith(TEMP_PREFIX)) {
      await unlink(join(directory, name));
      removed.push(name);
    }
  }
  if (removed.length > 0) await fsyncDirectory(directory);
  return removed;
}

/**
 * Read the authoritative file, refusing a symbolic link, a non-regular file
 * and a file over `maxBytes` before reading it. Returns `null` when it does
 * not exist.
 */
export async function readSnapshot(directory, maxBytes) {
  await requireDirectory(directory);
  let handle;
  try {
    handle = await open(join(directory, SNAPSHOT_NAME), FS.O_RDONLY | FS.O_NOFOLLOW);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    if (error.code === 'ELOOP') throw new ArchiveLayoutError('the snapshot is a symbolic link');
    throw error;
  }
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new ArchiveLayoutError('the snapshot is not a regular file');
    if (info.size > maxBytes) throw new ArchiveLayoutError('the snapshot is larger than the configured bound');
    const bytes = new Uint8Array(info.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) throw new ArchiveLayoutError('the snapshot changed while it was read');
      offset += bytesRead;
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

/**
 * Replace the authoritative file with `bytes`. `hook(step)` is awaited before
 * each step of WRITE_STEPS (tests use it to stop the process there). A
 * failure before the rename leaves the authoritative file untouched and is
 * thrown as is, after a best-effort removal of the temporary file; any failure from the
 * rename on (including the `directory-fsync` and `reported` hooks) is an UncertainWriteError.
 */
export async function writeSnapshot(directory, bytes, hook) {
  const temp = join(directory, TEMP_PREFIX + randomBytes(8).toString('hex'));
  let handle = null;
  try {
    await hook('temp-create');
    handle = await open(temp, FS.O_WRONLY | FS.O_CREAT | FS.O_EXCL | FS.O_NOFOLLOW, 0o600);
    await hook('temp-write');
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
      offset += bytesWritten;
    }
    await hook('temp-fsync');
    await handle.sync();
    await hook('temp-close');
    await handle.close();
    handle = null;
    await hook('rename');
  } catch (error) {
    if (handle !== null) await handle.close().catch(() => undefined);
    await unlink(temp).catch(() => undefined);
    throw error;
  }
  try {
    await rename(temp, join(directory, SNAPSHOT_NAME));
  } catch (error) {
    await unlink(temp).catch(() => undefined);
    throw new UncertainWriteError('the snapshot rename failed', { cause: error });
  }
  try {
    await hook('directory-fsync');
    await fsyncDirectory(directory);
    await hook('reported');
  } catch (error) {
    // After the rename every failure, even one after the fsync, leaves the outcome unknown to the caller.
    throw new UncertainWriteError('the write after the rename did not complete', { cause: error });
  }
}
