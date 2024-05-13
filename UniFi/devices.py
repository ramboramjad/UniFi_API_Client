#!/usr/bin/python3

import logging
import requests
import json


def force_provision(self, mac):
    """ Force device Provisioning
    :param mac: Required
    :return: A list of clients on the format of a dict
    """
    payload = json.dumps({"cmd": "force-provision", "mac": str(mac).lower()})

    resp = self._session.post("{}/api/s/{}/cmd/devmgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("FORCE PROVISION\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def adopt_device(self, mac):
    payload = json.dumps({"cmd": "adopt", "mac": str(mac).lower()})

    resp = self._session.post("{}/api/s/{}/cmd/devmgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("ADOPT DEVICE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def rename_device(self, device_id, device_name):
    payload = json.dumps({"name": device_name})

    resp = self._session.post("{}/api/s/{}/upd/device/{}".format(self._baseurl, self._site, device_id),
                              verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("RENAME DEVICE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def delete_device(self, mac):
    payload = json.dumps({"mac": str(mac).lower(),
                          "cmd": "delete-device"})

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site),
                              verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("DELETE DEVICE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def move_device(self, mac, site_id):
    payload = json.dumps({"mac": mac,
                          "cmd": "move-device",
                          "site": site_id})

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site),
                              verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("MOVE DEVICE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def upgrade_device(self, mac):
    payload = json.dumps({"mac": str(mac).lower()})

    resp = self._session.post("{}/api/s/{}/cmd/devmgr/upgrade".format(self._baseurl, self._site),
                              verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UPGRADE DEVICE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def add_tag(self, mac, tag):
    payload = json.dumps({"member_table": [mac.lower()], "name": tag})

    resp = self._session.post("{}/api/s/{}/rest/tag".format(self._baseurl, self._site),
                              verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("ADD TAG\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def add_snmp(self, devid, snmp):
    payload = json.dumps({"snmp_location": snmp})

    resp = self._session.put("{}/api/s/{}/rest/device/{}".format(self._baseurl, self._site, devid),
                             verify=self._verify_ssl, data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("ADD SNMP\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data
