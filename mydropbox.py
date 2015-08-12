#!/usr/bin/python

import os
from dropbox import client, rest
from dropbox.client import format_path
import json
import sys

import re
import binascii
import subprocess
import logging

from settings import APP_KEY, APP_SECRET

import urllib3
urllib3.disable_warnings()

HOME = os.path.expanduser('~')


class MyDropbox(object):
    def __init__(self, filepath=None, account_type=None, *args, **kwargs):
        self.filepath = filepath
        self._symlinked_path = os.path.join(HOME, 'Dropbox')
        self.account_type = account_type or self._get_account_type()

    @classmethod
    def get_by_filepath(cls, filepath):
        return cls(filepath)

    @classmethod
    def get_by_account(cls, account_type='personal'):
        return cls(account_type=account_type)

    @property
    def dropbox_filepath(self):
        return self.filepath.replace(self.dropbox_folder, '') if self.filepath else ''

    @property
    def dropbox_folder(self):
        if self._is_symlinked_path:
            return self._symlinked_path
        return self.get_dropbox_path(self.account_type)['path']

    @staticmethod
    def keychain():
        try:
            return KeyChain()
        except:
            print "Unable to access keychain. Quitting..."
            sys.exit()

    def get_client(self):
        access_token = self._get_access_token(self.account_type)
        return client.DropboxClient(access_token)

    @staticmethod
    def get_dropbox_path(account=None):
        path_file = os.path.join(HOME, '.dropbox', 'info.json')
        path_info = json.load(open(path_file))
        return path_info.get(account, path_info) if account else path_info

    def share_link(self, path=None, short_url=False, *args, **kwargs):
        if not path:
            path = self.filename
        dbclient = self.get_client()

        path = "/shares/%s%s" % (dbclient.session.root, format_path(path))

        kwargs['short_url'] = short_url

        url, params, headers = dbclient.request(path, kwargs,  method='GET')

        return dbclient.rest_client.GET(url, headers)

    def search(self, base, filename):
        dbclient = self.get_client()
        try:
            return dbclient.search(base, filename)
        except:
            return None

    ###########
    # Auth Flow #
    ###########

    @classmethod
    def link_account(cls):
        possible_accounts = MyDropbox.get_dropbox_path()
        chosen_account = None
        while chosen_account not in possible_accounts.keys():
            chosen_account = raw_input(
                'Choose an account: {}: '.format(map(str, possible_accounts.keys()))
            ).strip().lower()

        print """

Please go to the following link:

{}

Once you've received the auth code, return and enter it here

""".format(MyDropbox.get_auth_url())

        auth_code = raw_input("Enter code here: ").strip()
        MyDropbox.authorize(auth_code)

        print "Congrats! You're now linked to your {} account!".format(chosen_account)
        return

    @staticmethod
    def get_auth_url():
        flow = client.DropboxOAuth2FlowNoRedirect(
            APP_KEY, APP_SECRET)
        return flow.start()

    @staticmethod
    def authorize(auth_code):
        flow = client.DropboxOAuth2FlowNoRedirect(
            APP_KEY, APP_SECRET)
        try:
            access_token, user_id = flow.finish(auth_code)

            access_tokens = {}
            try:
                access_tokens = json.loads(
                    MyDropbox.keychain().get_password('dropbox_access_tokens'))
            except PasswordNotFound:
                pass

            dbclient = client.DropboxClient(access_token)
            account_type = 'business' if dbclient.account_info().get('team') \
                else 'personal'
            access_tokens[account_type] = {
                'user_id': user_id,
                'access_token': access_token
            }
            MyDropbox.keychain().save_password(
                'dropbox_access_tokens',
                json.dumps(access_tokens)
            )
        except rest.ErrorResponse, e:
            print 'Error: %s' % (e,)

        return 0

    #################
    # Private Methods #
    #################

    def _is_symlinked_path(self):
        dropbox_paths = [account_info['path']
                         for _, account_info in self.get_dropbox_path().iteritems()]
        if (not any(db_path in self.filepath for db_path in dropbox_paths)
                and self._symlinked_path in self.filepath):
            return True
        return False

    def _get_account_type(self):
        file_to_check = self.filepath
        if self._is_symlinked_path():
            file_to_check = self.filepath.replace(
                self._symlinked_path,
                os.path.abspath(os.readlink(self._symlinked_path))
            )
        for account_type, info in self.get_dropbox_path().iteritems():
            if info['path'] in file_to_check:
                return account_type

    def _relative_path(self):
        dropbox_folder = self._which_dropbox_folder()
        return self.filepath.replace(dropbox_folder, '')

    def _get_access_token(self, account_type):
        tokens = json.loads(
            MyDropbox.keychain().get_password('dropbox_access_tokens', 'ryanmo.dropbox.service'))
        try:
            return tokens[account_type]['access_token']
        except KeyError:
            raise PasswordNotFound(
                "No password found for {}, {}".format(
                    account_type, self.filepath)
            )

"""
Credit for keychain helpers goes to deanishe from alfred-workflow
https://github.com/deanishe/alfred-workflow
"""

####################################################################
# Keychain access errors
####################################################################


class KeychainError(Exception):
    """Raised by methods :meth:`Workflow.save_password`,
    :meth:`Workflow.get_password` and :meth:`Workflow.delete_password`
    when ``security`` CLI app returns an unknown error code.

    """


class PasswordNotFound(KeychainError):
    """Raised by method :meth:`Workflow.get_password` when ``account``
    is unknown to the MyDropbox.Keychain().

    """


class PasswordExists(KeychainError):
    """Raised when trying to overwrite an existing account password.

    You should never receive this error: it is used internally
    by the :meth:`Workflow.save_password` method to know if it needs
    to delete the old password first (a Keychain implementation detail).

    """
####################################################################
# Keychain password storage methods
####################################################################


class KeyChain(object):
    def __init__(self):
        self._logger = None

    @property
    def logger(self):
        """Create and return a logger that logs to both console and
        a log file.

        Use :meth:`open_log` to open the log file in Console.

        :returns: an initialised :class:`~logging.Logger`

        """

        if self._logger:
            return self._logger

        # Initialise new logger and optionally handlers
        logger = logging.getLogger('workflow')

        if not len(logger.handlers):  # Only add one set of handlers
            console = logging.StreamHandler()

            fmt = logging.Formatter(
                '%(asctime)s %(filename)s:%(lineno)s'
                ' %(levelname)-8s %(message)s',
                datefmt='%H:%M:%S')

            console.setFormatter(fmt)

            logger.addHandler(console)

        logger.setLevel(logging.DEBUG)
        self._logger = logger

        return self._logger

    @logger.setter
    def logger(self, logger):
        """Set a custom logger.

        :param logger: The logger to use
        :type logger: `~logging.Logger` instance

        """

        self._logger = logger

    def save_password(self, account, password, service='ryanmo.dropbox.service'):
        """Save account credentials.

        If the account exists, the old password will first be deleted
        (Keychain throws an error otherwise).

        If something goes wrong, a :class:`KeychainError` exception will
        be raised.

        :param account: name of the account the password is for, e.g.
            "Pinboard"
        :type account: ``unicode``
        :param password: the password to secure
        :type password: ``unicode``
        :param service: Name of the service.
        :type service: ``unicode``

        """

        try:
            self._call_security('add-generic-password', service, account,
                                '-w', password)
            # self.logger.debug('Saved password : %s:%s', service, account)

        except PasswordExists:
            # self.logger.debug('Password exists : %s:%s', service, account)
            current_password = self.get_password(account, service)

            if current_password == password:
                pass
                # self.logger.debug('Password unchanged')

            else:
                self.delete_password(account, service)
                self._call_security('add-generic-password', service,
                                    account, '-w', password)
                # self.logger.debug('save_password : %s:%s', service, account)

    def get_password(self, account, service='ryanmo.dropbox.service'):
        """Retrieve the password saved at ``service/account``. Raise
        :class:`PasswordNotFound` exception if password doesn't exist.

        :param account: name of the account the password is for, e.g.
            "Pinboard"
        :type account: ``unicode``
        :param service: Name of the service.
        :type service: ``unicode``
        :returns: account password
        :rtype: ``unicode``

        """

        output = self._call_security('find-generic-password', service,
                                     account, '-g')

        # Parsing of `security` output is adapted from python-keyring
        # by Jason R. Coombs
        # https://pypi.python.org/pypi/keyring
        m = re.search(
            r'password:\s*(?:0x(?P<hex>[0-9A-F]+)\s*)?(?:"(?P<pw>.*)")?',
            output)

        if m:
            groups = m.groupdict()
            h = groups.get('hex')
            password = groups.get('pw')
            if h:
                password = unicode(binascii.unhexlify(h), 'utf-8')

        # self.logger.debug('Got password : %s:%s', service, account)

        return password

    def delete_password(self, account, service='ryanmo.dropbox.service'):
        """Delete the password stored at ``service/account``. Raises
        :class:`PasswordNotFound` if account is unknown.

        :param account: name of the account the password is for, e.g.
            "Pinboard"
        :type account: ``unicode``
        :param service: Name of the service.
        :type service: ``unicode``

        """

        self._call_security('delete-generic-password', service, account)

        # self.logger.debug('Deleted password : %s:%s', service, account)

    def _call_security(self, action, service, account, *args):
        """Call the ``security`` CLI app that provides access to keychains.


        May raise `PasswordNotFound`, `PasswordExists` or `KeychainError`
        exceptions (the first two are subclasses of `KeychainError`).

        :param action: The ``security`` action to call, e.g.
                           ``add-generic-password``
        :type action: ``unicode``
        :param service: Name of the service.
        :type service: ``unicode``
        :param account: name of the account the password is for, e.g.
            "Pinboard"
        :type account: ``unicode``
        :param password: the password to secure
        :type password: ``unicode``
        :param *args: list of command line arguments to be passed to
                      ``security``
        :type *args: `list` or `tuple`
        :returns: ``(retcode, output)``. ``retcode`` is an `int`, ``output`` a
                  ``unicode`` string.
        :rtype: `tuple` (`int`, ``unicode``)

        """

        cmd = ['security', action, '-s', service, '-a', account] + list(args)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        retcode, output = p.wait(), p.stdout.read().strip().decode('utf-8')
        if retcode == 44:  # password does not exist
            raise PasswordNotFound()
        elif retcode == 45:  # password already exists
            raise PasswordExists()
        elif retcode > 0:
            err = KeychainError('Unknown Keychain error : %s' % output)
            err.retcode = retcode
            raise err
        return output

