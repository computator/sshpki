import os
import errno
import fcntl
import tempfile

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

def _sign_key(ca_key, key, identity, host_key=False, principals=None, validity=None):
    pass

def sign_key(pki_root, ca_key, key, identity, principals, validity, host_key=False, key_is_str=False):
    pass

def find_cert(pki_root, key, key_is_str=False):
    pass
