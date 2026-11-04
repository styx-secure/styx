// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MdkB33aProcess } from '../../spikes/marmot-phase-b3-3a/b3-3a-mdk-driver.mjs';

// Scripted stand-ins for the peer's stdio contract only (no MLS). The
// quarantine script closes its stdin before it answers, which is the state the
// real peer reaches when it exits after an RpcError with terminate = true and
// the driver has not yet observed the exit: a later write gets EPIPE.
const QUARANTINE_PEER = `#!/bin/sh
IFS= read -r _request
exec 0<&-
printf '%s\\n' '{"id":1,"ok":false,"error":{"code":"mdk_peer_quarantined","details":null,"message":"synthetic quarantine"}}'
sleep 0.3
: > "\${0%/*}/quarantine-exited"
exit 0
`;
const CHECKPOINT_PEER = `#!/bin/sh
IFS= read -r request
case "$request" in
  *'"id":1,"op":"checkpoint_and_exit"'*)
    printf '%s\\n' '{"id":1,"ok":true,"result":{"checkpointed":true}}' ;;
  *)
    printf '%s\\n' '{"id":1,"ok":false,"error":{"code":"invalid_request","details":null,"message":"unexpected request"}}' ;;
esac
exit 0
`;

describe('Phase B3.3a MDK driver close boundary', () => {
  let directory;
  const script = (name, body) => {
    const path = join(directory, name);
    writeFileSync(path, body);
    chmodSync(path, 0o700);
    return path;
  };

  beforeAll(() => { directory = mkdtempSync(join(tmpdir(), 'styx-b33a-driver-')); });
  afterAll(() => { rmSync(directory, { recursive: true, force: true }); });

  test('close after a quarantine response waits for the exit and never writes', async () => {
    const mdk = new MdkB33aProcess(script('quarantine-peer.sh', QUARANTINE_PEER));
    await expect(mdk.request('ingest_group_message', { group_message_hex: '00' }))
      .rejects.toMatchObject({ code: 'mdk_peer_quarantined' });
    await expect(mdk.close()).resolves.toBeUndefined();
    // The stand-in writes this marker just before it exits.
    expect(existsSync(join(directory, 'quarantine-exited'))).toBe(true);
  });

  test('close of a live peer still requests checkpoint_and_exit', async () => {
    const mdk = new MdkB33aProcess(script('checkpoint-peer.sh', CHECKPOINT_PEER));
    await expect(mdk.close()).resolves.toBeUndefined();
  });
});
