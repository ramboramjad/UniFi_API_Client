#!/usr/bin/python3
import requests
import json
import logging


def get_settings(self):
    resp = self._session.get("{}/api/s/{}}/get/setting".format(self._baseurl, self._site, verify=self._verify_ssl))

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("GET COMPLETE SITE SETTINGS\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_usergroup(self):
    """ List all available user groups per site
    :return: True and a list of user groups (dict) or false
    """
    resp = self._session.get("{}/api/s/{}/list/usergroup".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")
    self._current_status_code = resp.status_code

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST USERGROUPS\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_wlangroup(self):
    """ List all available wlan groups per site
    :return: True and a list of wlan groups (dict) or false
    """
    resp = self._session.get("{}/api/s/{}/list/wlangroup".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")
    self._current_status_code = resp.status_code

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST WLANGROUPS\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_wlanconf(self, wlan_id):
    """ List all available wlans per site
    :param wlan_id: Optional
    :return: True and a list of wlans (dict) or false
    """
    if wlan_id is not None:
        resp = self._session.get(
            "{}/api/s/{}/rest/wlanconf/{}".format(self._baseurl, self._site, wlan_id, verify=self._verify_ssl),
            data="json={}")
    else:
        resp = self._session.get("{}/api/s/{}/rest/wlanconf".format(self._baseurl, self._site, verify=self._verify_ssl),
                                 data="json={}")
    self._current_status_code = resp.status_code

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST WLANCONF\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_sites(self):
    """ List all available sites from the api
    :return: True and a list of sites (dict) or False
    """

    resp = self._session.get("{}/api/self/sites".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST SITES\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_devices(self):
    """ List all available devices from the api
    :return: True and a list of devices (dict) or False
    """
    resp = self._session.get("{}/api/s/{}/stat/device".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST DEVICES\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_clients(self):
    """ List all available clients from the api
    :return: True and a  list of clients (dict) or False
    """
    resp = self._session.get("{}/api/s/{}/stat/sta".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST CLIENTS\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_health(self):
    """ List health metrics
    :return: True and a health metrics (dict) or False
    """
    resp = self._session.get("{}/api/s/{}/stat/health".format(self._baseurl, self._site, verify=self._verify_ssl),
                             data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST HEALTH\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_dashboard(self, five_minutes):
    if five_minutes:
        resp = self._session.get(
            "{}/api/s/{}/stat/dashboard".format(self._baseurl, self._site, verify=self._verify_ssl),
            data="json={}")
    else:
        resp = self._session.get(
            "{}/api/s/{}/stat/dashboard".format(self._baseurl, self._site, verify=self._verify_ssl),
            data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST DASHBOARD\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def status_controller(self):
    try:
        resp = requests.get("{}/status".format(self._baseurl), verify=self._verify_ssl)

        data = resp.json()['data']
        meta = resp.json()['meta']

        logging.debug("STATUS CONTROLLER\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

        if resp.status_code == 200:
            if meta['rc'] == 'ok':
                return True, meta
            else:
                logging.error("Error message: " + meta['msg'])
                return False, meta
    except:
        logging.error(" Controller is NOT running ")
        return False, "Controller is NOT running!"


def list_adoptable(self):
    resp = self._session.get("{}/api/s/{}/stat/device-basic".format(self._baseurl, self._site, verify=self._verify_ssl))
    #  stat/device
    #  stat/device-basic
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST ADOPTABLE\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_device(self, devserial):
    """ List single device from the api based on device serialnumber
        :return: True and a list of devices (dict) or False
        """
    resp = self._session.get(
        "{}/api/s/{}/stat/device/{}".format(self._baseurl, self._site, devserial, verify=self._verify_ssl),
        data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST SINGLE DEVICE\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_settings(self):
    resp = self._session.get(
        "{}/api/s/{}/get/setting".format(self._baseurl, self._site, verify=self._verify_ssl),
        data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST SETTINGS\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def list_ccode(self):
    resp = self._session.get(
        "{}/api/s/{}/stat/ccode".format(self._baseurl, self._site, verify=self._verify_ssl),
        data="json={}")

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("LIST CCODE\n------------\nData: %s\nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def testing(self):
    # do testing
    return None
