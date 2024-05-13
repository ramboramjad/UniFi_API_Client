#!/usr/bin/python3

import requests
import json
import logging


def unauthorize_guest(self, mac):
    """ Unauthorize a client device
    :return: A list of clients on the format of a dict
    """
    payload = json.dumps({"cmd": "unauthorize-guest", "mac": str(mac).lower()})

    resp = self._session.post("{}/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UNAUTHORIZE GUEST\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def authorize_guest(self, mac, min, up, down, limit, ap_mac):
    """
    authorize a client device
    :return: True if succes else False
    """
    payload = {"cmd": "authorize-guest", "mac": str(mac).lower(), "minutes": int(min)}

    if up is not None:
        payload["up"] = up
    if down is not None:
        payload["down"] = down
    if limit is not None:
        payload["bytes"] = limit
    if ap_mac is not None:
        payload["ap_mac"] = ap_mac

    resp = self._session.post("{}/api/s/{}/cmd/stamgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % json.dumps(payload))

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("AUTHORIZE GUEST\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data
