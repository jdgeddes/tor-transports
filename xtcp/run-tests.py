#!/usr/bin/python

import os
import signal
import sys
import subprocess
import time

libs = ['template', 'utp']
tests = ['filexfer', 'openssl', 'tgen']

def main():
    if len(sys.argv) == 1 or sys.argv[1].lower() not in libs:
        print 'Usage: {0} <XTCP library>'.format(sys.argv[0])
        print '\tLibraries: {0}'.format(' '.join(libs))
        return 0

    library = sys.argv[1].lower()

    env = dict(os.environ)
    if 'LD_LIBRARY_PATH' in env:
        env['LD_LIBRARY_PATH'] += ':' + os.getcwd()
    else:
        env['LD_LIBRARY_PATH'] = os.getcwd()
    env['LD_PRELOAD'] = os.path.join(os.getcwd(), 'libxtcp_{0}.so'.format(library))

    # for testdir in os.listdir('tests'):
    for testdir in tests:
        print testdir
        parentdir = os.path.join('tests', testdir)
        servercmd = './run-server.sh'
        clientcmd = './run-client.sh'

        if not os.path.exists(os.path.join(parentdir, servercmd)):
            print 'Cannot run test for {0}, no run-server.sh script'.format(testdir)
            continue

        if not os.path.exists(os.path.join(parentdir, clientcmd)):
            print 'Cannot run test for {0}, no run-client.sh script'.format(testdir)
            continue

        serverout = open(os.path.join(parentdir, 'server-out.log'), 'w')
        servererr = open(os.path.join(parentdir, 'server-err.log'), 'w')
        # env['XTCP_LOG'] = 'server-xtcp.log'
        serverproc = subprocess.Popen(servercmd, shell=True, stdout=serverout, stderr=serverout, env=env, cwd=parentdir)

        time.sleep(1)

        clientout = open(os.path.join(parentdir, 'client-out.log'), 'w')
        clienterr = open(os.path.join(parentdir, 'client-err.log'), 'w')
        # env['XTCP_LOG'] = 'client-xtcp.log'
        clientproc = subprocess.Popen(clientcmd, shell=True, stdout=clientout, stderr=clientout, env=env, cwd=parentdir)

        clientproc.wait()

        clientout.close()
        clienterr.close()
        serverout.close()
        servererr.close()

        os.kill(serverproc.pid, signal.SIGTERM)

if __name__ == '__main__':
    main()
