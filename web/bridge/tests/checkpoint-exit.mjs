// Test-only fault injection. Emit a checkpoint produced by the real bridge,
// then terminate as if the later analysis stage crashed. No fabricated report data.
import { spawnSync } from 'node:child_process';
const child = spawnSync(process.env.REAL_BRIDGE, [process.argv[2], '--stream'], { encoding: 'utf8' });
if (child.status !== 0) throw new Error(child.stderr);
process.stdout.write(child.stdout.split('\n')[0]+'\n', () => process.exit(17));
