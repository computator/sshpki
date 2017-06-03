import os
from os import path
import shutil
import errno
import fcntl
import tempfile
import subprocess
import re
import logging

class FileNotFoundError(Exception): pass
class ReadOnlyError(Exception): pass

log = logging.getLogger(__name__)

class SshPki:

    _fingerprint_cache = {}

    class _PkiLock:
        def __init__(self, pki):
            self.pki = pki

        def __enter__(self):
            self.lockf = open(path.join(self.pki.pki_root, '.serial.lock'), 'w')
            fcntl.flock(self.lockf, fcntl.LOCK_EX)

        def __exit__(self, *exception):
            fcntl.flock(self.lockf, fcntl.LOCK_UN)
            self.lockf.close()

    def __init__(self, pki_root, ca_privkey=None):
        self.pki_root = path.abspath(pki_root)
        self.ca_key = ca_privkey

        if not path.isdir(self.pki_root):
            raise FileNotFoundError("'{}' does not exist".format(self.pki_root))
        if self.ca_key and not path.isfile(self.ca_key):
            raise FileNotFoundError("'{}' does not exist".format(self.ca_key))

        self.certsdir = path.join(self.pki_root, 'certs')
        if not path.isdir(self.certsdir):
            os.mkdir(self.certsdir)
            
        self.lock = self._PkiLock(self)

    def _get_new_serial(self):
        with self.lock:
            old_serial = 0
            try:
                with open(path.join(self.pki_root, 'serial'), 'r') as serial_file:
                    old_serial = int(serial_file.read(32))
            except IOError as err:
                if err.errno is not errno.ENOENT:
                    raise err
            with tempfile.NamedTemporaryFile('w', dir=self.pki_root, delete=False) as new_file:
                new_file.write(str(old_serial + 1))
                temp_name = new_file.name
            os.rename(temp_name, path.join(self.pki_root, 'serial'))
        return old_serial + 1

    def sign_key(self, identity, principals, validity, host_key=False, keystr=None, keyfile=None):
        if not keystr and not keyfile:
            raise RuntimeError("Either 'keystr' or 'keyfile' must be specified")
        elif keyfile and keystr:
            raise RuntimeError("Only one of 'keystr' or 'keyfile' can be specified")

        if not self.ca_key:
            raise ReadOnlyError("No CA Key loaded")
        if keyfile:
            if not path.isfile(keyfile):
                raise FileNotFoundError("'{}' does not exist".format(keyfile))
            with open(keyfile, 'r') as key_tmp:
                key = key_tmp.read(4096)
        else:
            key = keystr

        with _TempDir(self.pki_root) as tmpdir:
            with tempfile.NamedTemporaryFile('w', dir=tmpdir, delete=False) as key_copy:
                key_copy.write(key)
                keypath = key_copy.name
            if key in self._fingerprint_cache:
                fingerprint = self._fingerprint_cache[key]
            else:
                fingerprint = _get_fingerprint(keypath)
                self._fingerprint_cache[key] = fingerprint
            certpath = path.join(self.certsdir, fingerprint)
            out_cert = _sign_key(self.ca_key, keypath, identity, self._get_new_serial(), principals, validity, host_key)
            os.rename(out_cert, certpath)
        return certpath

    def find_cert(self, keystr=None, keyfile=None):
        if not keystr and not keyfile:
            raise RuntimeError("Either 'keystr' or 'keyfile' must be specified")
        elif keyfile and keystr:
            raise RuntimeError("Only one of 'keystr' or 'keyfile' can be specified")

        if keyfile:
            if not path.isfile(keyfile):
                raise FileNotFoundError("'{}' does not exist".format(keyfile))
            with open(keyfile, 'r') as key_tmp:
                key = key_tmp.read(4096)
        else:
            key = keystr

        if key in self._fingerprint_cache:
            fingerprint = self._fingerprint_cache[key]
        else:
            keypath = None
            try:
                with tempfile.NamedTemporaryFile('w', dir=self.pki_root, delete=False) as key_copy:
                    key_copy.write(key)
                    keypath = key_copy.name
                fingerprint = _get_fingerprint(keypath)
            finally:
                if keypath:
                    os.remove(keypath)
            self._fingerprint_cache[key] = fingerprint

        certpath = path.join(self.certsdir, fingerprint)
        if path.exists(certpath):
            return certpath

class _TempDir:
    def __init__(self, parentdir):
        self.path = parentdir

    def __enter__(self):
        self.tmpdir = tempfile.mkdtemp(dir=self.path)
        return self.tmpdir

    def __exit__(self, *exception):
        shutil.rmtree(self.tmpdir)

def _sign_key(ca_key, key, identity, serial, principals=None, validity=None, host_key=False):
    args = ['ssh-keygen', '-s', ca_key, '-I', identity, '-z', str(serial)]
    if host_key:
        args.append('-h')
    if principals:
        args.extend(['-n', ','.join(principals)])
    if validity:
        args.extend(['-V', validity])
    args.append(key)
    try:
        output = subprocess.check_output(args, stderr=subprocess.STDOUT).strip()
    except subprocess.CalledProcessError as e:
        log.error("ssh-keygen returned an error: %s", e.output)
        raise e
    log.info("%s", output)
    return key + '-cert.pub'

def _get_fingerprint(keyfile):
    try:
        output = subprocess.check_output(['ssh-keygen', '-l', '-f', keyfile], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        log.error("ssh-keygen returned an error: %s", e.output)
        raise e
    fingerprint = re.match(r'\d+\s+(?:(?:SHA256|MD5):)?([^\s]+)', output).group(1).replace(':', '')
    log.debug("Fingerprint for %s: %s", keyfile, fingerprint)
    return fingerprint.replace('+', '-').replace('/', '_')

