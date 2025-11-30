"""
This module provides a Python interface to interact with the
Osmocom Control Interface.

Example:
    ctrl = CtrlInterface('127.0.0.1', 4259)

    try:
        ctrl_resp = ctrl.get('subscriber.by-msisdn-001.info-all')

        print(ctrl_resp)
    except CtrlError as e:
        raise e
"""

from random import randint
from sys import maxsize

import socket
import struct
import time

# IPAC stream identifier is 0xEE, and Extension Attribute for CTRL interface is 0x00.
# Collected from https://ftp.osmocom.org/docs/osmo-hlr/master/osmohlr-usermanual.pdf
# Section 11.1 "Control Interface Protocol"
IPAC_PROTO_OSMO = 0xEE
OSMO_CTRL = 0x00

# Default value parsing behaviour (if not specified elsewhere)
PARSE_VAL_DEFAULT = True

class CtrlError(Exception):
    """Raised when the control interface returns an error."""
    pass

class CtrlInterface:
    """This class represents the Osmocom Control Interface connection,
    and is used to "get" and "set" vars.

    :param server: The IP address of the Osmocom Control Interface host.
    :type server: str
    :param port: The port of the Osmocom Control Interface.
    :type port: int
    :param timeout: The maximum time to wait for a response to a message, defaults to 10 seconds.
    :type timeout: int, optional
    """
    
    def __init__(self, server: str, port: int, timeout=10):
        ## Connect to Osmocom Control Interface via socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server, port))
        
        self._ctrl_socket = s
        self._timeout = timeout
        self._TRAPS = []

    def _decode_val(self, val: str):
        """Attempt to decode a returned val into a dict.
        The Osmocom Control Interface isn't particularly great at returning
        values that are easy to parse. This attempts to parse a returned value
        into a dict so that it can be used programmatically.

        :param val: The input value to be parsed.
        :type val: str

        :return: A dict containing the parsed value.
        :rtype: dict

        :raises Exception: If the value cannot be parsed.
        """

        val_dict = {}

        # Split away any whitespace, in prep to get key / value
        for key_value in val.split('\n'):
            if key_value:
                key_value_split = key_value.split('\t')
                
                if len(key_value_split) <= 1:
                    # If length of split is <= 1, it's likely
                    # that the returned value is a single value on
                    # it's own. Simply return this as the value.
                    value_split = key_value_split[0].split(' ')
                    
                    if len(value_split) > 1:
                        val_dict['value'] = value_split
                    else:
                        val_dict['value'] = key_value_split[0]
                    
                    break
                
                # Each split should now contain a key and it's value
                key = key_value_split[0]
                value = key_value_split[1]
                
                val_dict[key] = value
        
        # If nothing, we failed to create a valid key / value split
        if not val_dict: raise Exception('Unable to decode val to dict.',
                                         val)
        
        # Make empty key values nicer to use programmatically
        for key, value in val_dict.items():
            if value == 'none': val_dict[key] = None
        
        return val_dict

    def _decode_ctrl_msg(self, cmd_id: str, msg: bytes, parse_val = PARSE_VAL_DEFAULT):
        """Attempt to decode a message received over CTRL interface.

        :param cmd_id: The command ID issued as part of the initial request.
        :type cmd_id: str
        :param msg: The received message.
        :type msg: bytes
        :param parse_val: Should the message be parsed? (default True)
        :type parse_val: bool, optional

        :return: A dict containing the decoded message.
        :rtype: dict

        :raises Exception: If the command ID returned does not match the initial request (wrong message).
        """

        decoded_msg = msg.decode('utf-8')

        msg_outcome = (decoded_msg.split(' ', 1))[0]

        # Setup dict keys for each outcome
        if msg_outcome == 'GET_REPLY' or msg_outcome == 'SET_REPLY':
            msg_attributes = ['outcome', 'cmd_id', 'var', 'val']
            msg_split = decoded_msg.split(' ', 3)
        elif msg_outcome == 'ERROR':
            msg_attributes = ['outcome', 'cmd_id', 'reason']
            msg_split = decoded_msg.split(' ', 2)
        elif msg_outcome == 'TRAP':
            msg_attributes = ['outcome', 'var', 'val']
            msg_split = decoded_msg.split(' ', 2)
        else:
            return None

        # Match keys to values
        resp_dict = dict(zip(msg_attributes, msg_split))

        if 'cmd_id' in resp_dict and resp_dict['cmd_id'] != cmd_id:
            raise Exception('Command ID mismatch!',
                            'Something has gone quite wrong, msg response not matching request.',
                            decoded_msg, cmd_id)
        
        # If we have a value, and parsing is enabled, parse that value
        if 'val' in resp_dict and parse_val == True:
            resp_dict['val'] = self._decode_val(resp_dict['val'])

        return resp_dict
    
    def _process_ctrl_resp(self, cmd_id: str, parse_val = PARSE_VAL_DEFAULT):
        """Called after a command has been issued to wait for the response.

        :param cmd_id: The command ID issued as part of the initial request.
        :type cmd_id: str
        :param parse_val: Should the message be parsed? (default True)
        :type parse_val: bool, optional

        :return: A dict containing the decoded response message.
        :rtype: dict

        :raises CtrlError: If the response message contains an "ERROR" outcome.
        :raises Exception: If the response message is invalid or unable to be processed.
        """

        # Start a timeout, so we aren't left waiting forever if there's no response
        timeout = time.time() + self._timeout

        while True:
            if time.time() > timeout: raise Exception('No response within timeout',
                                                      f'{self._timeout} seconds')

            # Get the resp header from socket
            resp_header = self._ctrl_socket.recv(3)
            
            # Attempt to unpack the struct
            (data_length, protocol) = struct.unpack('>HB', resp_header)

            # If resp header proto == IPAC_PROTO_OSMO (0xEE), proceed to read extension
            if protocol == IPAC_PROTO_OSMO:
                resp_header += self._ctrl_socket.recv(1)

                ipac_proto_extension = struct.unpack('>HBB', resp_header)[2]

                # If extension == OSMO_CTRL (0x00), this is an Osmocom Control Interface header
                if ipac_proto_extension == OSMO_CTRL:
                    # Get the message beyond the header using length stated in header, +1
                    resp_data = self._ctrl_socket.recv(data_length+1)

                    # Decode the message received
                    decoded_ctrl_msg = self._decode_ctrl_msg(cmd_id, resp_data, 
                                                             parse_val)

                    # If the message was decoded correctly, read outcome and determine if error. If not,
                    # return decoded msg.
                    if decoded_ctrl_msg:
                        if decoded_ctrl_msg['outcome'] == 'ERROR':
                            raise CtrlError(decoded_ctrl_msg['outcome'], decoded_ctrl_msg['reason'],
                                            decoded_ctrl_msg)
                        elif decoded_ctrl_msg['outcome'] == 'TRAP':
                            self._TRAPS.append(decoded_ctrl_msg)
                        else:
                            return decoded_ctrl_msg
                    else:
                        raise Exception('Unable to process message!', resp_data)
                    
                    time.sleep(0.5)
            else:
                raise Exception('Incorrect Protocol / Invalid Response!', resp_header)

    def _send_cmd(self, var: str, val = None, parse_val = PARSE_VAL_DEFAULT):
        """Called to send a command to CTRL interface.

        :param var: The var to get / set.
        :type val: str
        :param var: The val the var should be set to, used for the set operation (default None)
        :type var: str, optional
        :param parse_val: Should the message be parsed? (default True)
        :type val: bool, optional

        :return: A dict containing the decoded response message.
        :rtype: dict
        """

        # Generate a random(ish) command ID, just to ensure the response is for
        # the correct command.
        cmd_id = str(randint(1, maxsize))

        # If we have a value, this is a 'SET' operation. Otherwise, it's a 'GET'.
        if val:
            cmd = f'SET {cmd_id} {var} {val}'
        else:
            cmd = f'GET {cmd_id} {var}'

        # Encode into bytes as UTF-8
        cmd_enc = cmd.encode('utf-8')

        # Pack into a struct, ready to be sent over the socket
        packed_data = struct.pack(">HBB", len(cmd_enc) + 1,
                                  IPAC_PROTO_OSMO, OSMO_CTRL) + cmd_enc
        
        # Send over the socket to CTRL interface
        self._ctrl_socket.sendall(packed_data)

        # Return self._process_ctrl_resp(), which returns a dict of the decoded
        # response message once received.
        return self._process_ctrl_resp(cmd_id, parse_val)

    def get(self, var: str, parse_val = PARSE_VAL_DEFAULT):
        """Get a variable via the Osmocom Control Interface.

        :param var: The variable to retrieve.
        :type var: str
        :param parse_val: Should the returned value be parsed? (default True)
        :type parse_val: bool, optional
        
        :return: A dict containing the result of your variable query.
        :rtype: dict

        :raises CtrlError: If the Control Interface raises an error at the request.
        """

        return self._send_cmd(var, parse_val=parse_val)
    
    def set(self, var: str, val: str, parse_val = PARSE_VAL_DEFAULT):
        """Set a variable via the Osmocom Control Interface.

        :param var: The variable to set.
        :type var: str
        :param val: The new value of the variable.
        :type val: str
        :param parse_val: Should the returned value be parsed? (default True)
        :type parse_val: bool, optional
        
        :return: A dict containing the result of your set command.
        :rtype: dict

        :raises CtrlError: If the Control Interface raises an error at the request.
        """

        return self._send_cmd(var, val, parse_val)

    @property
    def TRAPS(self):
        """Pop the list of TRAPS recieved.
        
        :return: A list containing all TRAPS recieved since last check.
        :rtype: list
        """

        return [self._TRAPS.pop(0) for _ in range(len(self._TRAPS))]

    @TRAPS.setter
    def TRAPS(self, val):
        """Append to the list of TRAPS recieved."""
        self._TRAPS.append(val)
