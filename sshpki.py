import os
import shutil
import errno
import fcntl
import tempfile
import subprocess
import re

class FileNotFoundError(Exception):
    pass

def _get_new_serial(pki_root):
    with open(os.path.join(os.path.abspath(pki_root), '.serial.lock'), 'w') as lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)
        try:
            with open(os.path.join(os.path.abspath(pki_root), 'serial'), 'r') as serial_file:
                old_serial = int(serial_file.read(32))
        except IOError as err:
            if err.errno is errno.ENOENT:
                old_serial = 0
            else:
                raise err
        with tempfile.NamedTemporaryFile('w', dir=os.path.abspath(pki_root), delete=False) as new_file:
            new_file.write(str(old_serial + 1))
            temp_name = new_file.name
        os.rename(temp_name, os.path.join(os.path.abspath(pki_root), 'serial'))
        fcntl.flock(lockf, fcntl.LOCK_UN)
    return old_serial + 1

def _sign_key(ca_key, key, identity, serial, principals=None, validity=None, host_key=False):
    args = ['ssh-keygen', '-q', '-s', ca_key, '-I', identity, '-z', str(serial)]
    if host_key:
        args.append('-h')
    if principals:
        args.extend(['-n', ','.join(principals)])
    if validity:
        args.extend(['-V', validity])
    args.append(key)
    subprocess.check_call(args)
    return key + '-cert.pub'

def _get_fingerprint(keyfile):
    output = subprocess.check_output(['ssh-keygen', '-l', '-f', keyfile])
    fingerprint = re.match(r'\d+\s+(?:(?:SHA256|MD5):)?([^\s]+)', output).group(1).replace(':', '')
    return fingerprint.replace('+', '-').replace('/', '_')

def sign_key(pki_root, ca_key, key, identity, principals, validity, host_key=False, key_is_str=False):
    if not os.path.isdir(pki_root):
        raise FileNotFoundError("'{}' does not exist".format(pki_root))
    if not os.path.isfile(ca_key):
        raise FileNotFoundError("'{}' does not exist".format(ca_key))
    if not key_is_str and not os.path.isfile(key):
        raise FileNotFoundError("'{}' does not exist".format(key))

    certsdir = os.path.join(os.path.abspath(pki_root), 'certs')
    if not os.path.isdir(certsdir):
        os.mkdir(certsdir)

    if not key_is_str:
        with open(key, 'r') as keyfile:
            key = keyfile.read(4096)

    tmpdir = tempfile.mkdtemp(dir=pki_root)
    try:
        with tempfile.NamedTemporaryFile('w', dir=tmpdir, delete=False) as key_copy:
            key_copy.write(key)
            keyfile = key_copy.name
        certfile = os.path.join(certsdir, _get_fingerprint(keyfile))
        out_cert = _sign_key(ca_key, keyfile, identity, _get_new_serial(pki_root), principals, validity, host_key)
        os.rename(out_cert, certfile)
    finally:
        shutil.rmtree(tmpdir)

    return certfile

def find_cert(pki_root, key, key_is_str=False):
    if not os.path.isdir(pki_root):
        raise FileNotFoundError("'{}' does not exist".format(pki_root))
    if not key_is_str and not os.path.isfile(key):
        raise FileNotFoundError("'{}' does not exist".format(key))

    certsdir = os.path.join(os.path.abspath(pki_root), 'certs')

    if not key_is_str:
        with open(key, 'r') as keyfile:
            key = keyfile.read(4096)

    keyfile = None
    try:
        with tempfile.NamedTemporaryFile('w', dir=os.path.abspath(pki_root), delete=False) as key_copy:
            key_copy.write(key)
            keyfile = key_copy.name
        certfile = os.path.join(certsdir, _get_fingerprint(keyfile))
    finally:
        if keyfile:
            os.remove(keyfile)

    if os.path.exists(certfile):
        return certfile
