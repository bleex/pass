#!/usr/bin/env python3

from __future__ import print_function

import argparse
import getpass
import os
import re
import traceback
import warnings

import paramiko
import yaml
from colorama import init, Fore
from paramiko_expect import SSHClientInteraction
from prettytable import PrettyTable, PLAIN_COLUMNS
from pykeepass import PyKeePass


class HostStatus:
    init()

    def __init__(self, hostname, status):
        self.hostname = hostname
        self.status = status

    def return_status(self):
        end = Fore.WHITE
        if self.status:
            color = Fore.GREEN
            status = 'changed'
        else:
            color = Fore.RED
            status = 'failed'

        ret = (color + self.hostname + end, color + status + end)
        return ret

    def print_status(self):
        stat = self.return_status()
        print(stat[0] + ' ' + stat[1])


class Host():
    CONST_PROMPT = r'.*[ ~][\$\#]\s*'
    CONST_OLDPWPROMPT = r'.*(password|hasło)\s*\:\s*'
    CONST_NEWPWPROMPT = r'.*(password|hasło)\s*\:\s*'
    CONST_NEWPWPROMPT2 = r'.*(password|hasło)\s*\:\s*'
    CONST_SUCCESSMSG = r'.*passwd\:.*(zmienione|successfully).*'
    updated = []

    warnings.filterwarnings("ignore", module='.*paramiko')

    def __init__(self, hostname, username, oldpwd, newpwd):
        self.hostname = hostname
        self.username = username
        self.oldpwd = oldpwd
        self.newpwd = newpwd
        self.changed = False
        self.log = []
        self.proxy = None
        ssh_config_file = os.path.expanduser('~/.ssh/config')
        if os.path.isfile(ssh_config_file):
            config = paramiko.SSHConfig()
            with open(ssh_config_file) as config_file:
                config.parse(config_file)
            host_config = config.lookup(hostname)
            if 'proxycommand' in host_config:
                self.proxy = host_config['proxycommand']

    def log_msg(self, message):
        self.log.append(message)

    def change_pwd(self, verbose):
        try:
            # Create a new SSH client object
            client = paramiko.SSHClient()

            # Set SSH key parameters to auto accept unknown hosts
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the host
            proxy = None
            if self.proxy is not None:
                proxy = paramiko.ProxyCommand(self.proxy)
            client.connect(hostname=self.hostname, timeout=20, sock=proxy,
                           username=self.username, password=self.oldpwd)

            with SSHClientInteraction(
                    client, timeout=10, display=False,
                    output_callback=lambda m: self.log_msg(m)) \
                    as interact:
                found_index = interact.expect(
                    [Host.CONST_PROMPT, Host.CONST_OLDPWPROMPT])
                if found_index == 0:
                    interact.send("passwd")
                    interact.expect(Host.CONST_OLDPWPROMPT)

                interact.send(self.oldpwd)
                interact.expect(Host.CONST_NEWPWPROMPT)
                interact.send(self.newpwd)
                interact.expect(Host.CONST_NEWPWPROMPT2)
                interact.send(self.newpwd)

                if found_index == 0:
                    interact.expect(Host.CONST_SUCCESSMSG)
                    interact.send('exit')
                interact.expect()
                self.changed = True
                client.close()

        except Exception:
            self.log_msg(traceback.format_exc())
        finally:
            try:
                client.close()
            except Exception:
                pass
        status = HostStatus(self.hostname, self.changed)
        Host.updated.append(status)
        if verbose:
            status.print_status()
            if not self.changed:
                print(self.log)


class KeePass():
    def __init__(self, password, cfgfile='pass.yml'):
        keyfile = None
        with open(cfgfile, 'r') as ymlfile:
            cfg = yaml.safe_load(ymlfile)['keepass']
            dbfile = cfg['dbfile']
            group = cfg['group']
            newentry = cfg['newentry']
            oldentry = cfg['oldentry']
            if 'keyfile' in cfg:
                keyfile = cfg['keyfile']
        self.keepass = PyKeePass(dbfile, password=password, keyfile=keyfile)
        self.group = self.keepass.find_groups(name=group, first=True)
        self.oldentry = self.keepass.find_entries(
            title=oldentry, group=self.group, first=True)
        self.newentry = self.keepass.find_entries(
            title=newentry, group=self.group, first=True)

    def get_hosts(self):
        hosts = self.oldentry.url
        ret = []
        for host in re.split(r'\s+', hosts):
            ret.append(Host(
                host, self.newentry.username, self.oldentry.password,
                self.newentry.password))
        return ret

    def add_to_url(self, host):
        if self.newentry.url is not None:
            self.newentry.url = self.newentry.url + ' ' + host
        else:
            self.newentry.url = host
        self.keepass.save()

    def add_to_notes(self, msg):
        if self.newentry.notes is not None:
            self.newentry.notes = self.newentry.notes + '\n' + msg
        else:
            self.newentry.notes = msg
        self.keepass.save()


def main():
    parser = argparse.ArgumentParser(description='Changes password on multiple hosts.')
    parser.add_argument('-f', '--file', nargs=1, help='Path to file with configuration.')
    parser.add_argument('-v', '--verbose', action='store_const', const=True, \
                        help='Verbose output.')
    args = parser.parse_args()
    cfgfilename = 'pass.yml'
    if args.file:
        cfgfilename = args.file[0]

    verbose = False
    if args.verbose:
        verbose = True
    password = getpass.getpass(prompt='KeePass2 Password: ')

    keepass = KeePass(password, cfgfile=cfgfilename)
    for host in keepass.get_hosts():
        host.change_pwd(verbose)
        if host.changed:
            keepass.add_to_url(host.hostname)
        else:
            keepass.add_to_notes(host.hostname + '\n' + '\n'.join(host.log))

    table = PrettyTable()
    table.field_names = ["hostname", "status"]
    table.set_style(PLAIN_COLUMNS)
    table.align = "l"

    for host in Host.updated:
        table.add_row(host.return_status())

    print(table)


if __name__ == '__main__':
    main()
