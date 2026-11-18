#!/usr/bin/env ucode
// fnport-update: update fnport from LuCI with the same installer as the README command.
//   fnport-update start   run the installer in the background
//   fnport-update status  print { running, log } as JSON
//   fnport-update run     what start runs, detached

import { readfile, writefile } from 'fs';

const SELF = '/usr/libexec/fnport-update';
const LOG = '/var/run/fnport-update.log'; // root-only directory
const PIDFILE = '/var/run/fnport-update.pid';
const INSTALLER = 'https://raw.githubusercontent.com/YUNGSLXRD/fnport/main/install.sh';

function running() {
	let pid = trim(readfile(PIDFILE) ?? '');
	return match(pid, /^[0-9]+$/) && index(readfile(`/proc/${pid}/cmdline`) ?? '', 'fnport-update') >= 0;
}

let cmd = ARGV[0];
if (cmd == 'status') {
	printf('%J\n', { running: !!running(), log: readfile(LOG) ?? '' });
}
else if (cmd == 'start') {
	if (running()) {
		printf('%J\n', { error: 'running' });
		exit(1);
	}
	writefile(LOG, '');
	// detached: the update replaces the LuCI files and restarts the service under rpcd's feet
	system([ 'start-stop-daemon', '-S', '-b', '-x', SELF, '--', 'run' ]);
	printf('%J\n', { started: true });
}
else if (cmd == 'run') {
	writefile(PIDFILE, split(readfile('/proc/self/stat') ?? '', ' ')[0]);
	let dl = `(uclient-fetch -q --timeout=30 -O /tmp/fnport-install.sh '${INSTALLER}' || wget -q -T 30 -O /tmp/fnport-install.sh '${INSTALLER}' || curl -fsSL --connect-timeout 10 --max-time 60 -o /tmp/fnport-install.sh '${INSTALLER}')`;
	system(`{ ${dl} && sh /tmp/fnport-install.sh; echo "exit $?"; } >${LOG} 2>&1`);
}
else {
	warn('usage: fnport-update start|status\n');
	exit(2);
}
