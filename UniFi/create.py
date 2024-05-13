#!/usr/bin/python3
import requests
import logging
from UniFi import refactoring
import pprint


def set_default_admin(self, admin, admin_email, admin_password):
    """ Setting default admin (part of the initialization)
    :param admin:
    :param admin_email:
    :param admin_password:
    :return: True or False
    """
    payload = {"cmd": "add-default-admin",
               "name": admin,
               "email": admin_email,
               "x_password": admin_password}

    resp = requests.post("{}/api/cmd/sitemgr".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 1 of 10\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_super_identity(self, site_name):
    """ set super identity (part of the initialization)
    :param self:
    :param site_name:
    :return: True or False
    """
    payload = {"name": site_name}

    resp = requests.post("{}/api/set/setting/super_identity".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 2 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_ccode(self, country):
    """ set country code (part of the initialization)
    :param self:
    :param country:
    :return: True or False
    """
    ccode = None
    resp = requests.get("{}/api/stat/ccode".format(self._baseurl), verify=self._verify_ssl)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 3 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] != 'ok':
        logging.error("Error message: " + meta['msg'])

    for count in data:
        if count["key"].upper() == country.upper():
            ccode = count["code"]
            logging.debug("ccode: " + ccode)

    payload = {"code": ccode}

    resp = requests.post("{}/api/set/setting/country".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 3.5 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_timezone(self, timezone):
    """ Set timezone (part of the initialization)
    :param self:
    :param timezone:
    :return: True or False
    """
    payload = {"timezone": timezone}

    resp = requests.post("{}/api/set/setting/locale".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 4 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_networkoptimization(self, network_optimization):
    """ Set networkoptomization (part of the initialization)
    :param self:
    :param network_optimization:
    :return: True or False
    """
    payload = {"enabled": network_optimization}
    resp = requests.post("{}/api/set/setting/network_optimization".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 5 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_autobackup(self):
    """ Set auto back-up (part of the initialization)
    :param self:
    :return: True or False
    """
    payload = {"autobackup_enabled": True,
               "autobackup_cron_expr": "0 0 1 * *",
               "autobackup_timezone": "UTC",
               "autobackup_days": 30,
               "backup_to_cloud_enabled": True}

    resp = requests.post("{}/api/set/setting/network_optimization".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 6 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_mgmt(self, admin_name, admin_password):
    """ Set management (part of the initialization)
    :param self:
    :param admin_name:
    :param admin_password:
    :return: True or False
    """
    admin_pass_hash = None
    import hashlib
    print(hashlib.sha1(admin_password.encode('utf-8')).hexdigest())

    payload = {"x_ssh_username": admin_name,
               "x_ssh_password": admin_pass_hash}

    resp = requests.post("{}/api/set/setting/mgmt".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 7 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_installed(self):
    payload = {"cmd": "set-installed"}

    resp = requests.post("{}/api/cmd/system".format(self._baseurl), verify=self._verify_ssl,
                         json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 8 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def set_self(self):
    """ set self (part of the initialization)
    :param self:
    :return: True or false
    """
    payload = {"last_site_name": "default"}

    resp = requests.put("{}/api/self".format(self._baseurl), verify=self._verify_ssl,
                        json=payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("INIT CONTROLLER - Part 9 of 9\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))
    if meta['rc'] == 'ok':
        return True
    else:
        logging.error("Error message: " + meta['msg'])
        return False


def init_controller(self, admin, admin_email, admin_password, site_name, country, timezone, network_optimization,
                    autobackup_enabled):
    """ Initialize Controller
    :param self:
    :param admin:
    :param admin_email:
    :param admin_password:
    :param site_name:
    :param country:
    :param timezone:
    :param network_optimization:
    :param autobackup_enabled:
    :return: True or False
    """
    succes = False

    if set_default_admin(self, admin, admin_email, admin_password):
        if set_super_identity(self, site_name):
            if set_ccode(self, country):
                if set_timezone(self, timezone):
                    if set_networkoptimization(self, network_optimization):
                        if autobackup_enabled:
                            set_autobackup(self)
                        # set_mgmt(self, admin, admin_password)
                        set_installed(self)
                        set_self(self)
                        succes = True
                    else:
                        logging.error(" Initialization FAILED - We got to part 5 ")
                else:
                    logging.error(" Initialization FAILED - We got to part 4 ")
            else:
                logging.error(" Initialization FAILED - We got to part 3 ")
        else:
            logging.error(" Initialization FAILED - We got to part 2 ")
    else:
        logging.error(" Initialization FAILED - We got to part 1 ")
    return succes


def create_site(self, description):
    """ Create a new site within controller (can ONLY be done by super-admin)
    :param description:
    :return: True or False
    """
    payload = {'desc': description, 'cmd': 'add-site'}

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE SITE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def create_usergroup(self, group_name, group_dn, group_up):
    """ Create a new usergroup
    :param group_name: required
    :param group_dn: optional (default unlimited (-1))
    :param group_up: optional (default unlimited (-1))
    :return: True or False
    """
    payload = {'name': group_name, 'qos_rate_max_down': int(group_dn), 'qos_rate_max_up': int(group_up)}

    resp = self._session.post("{}/api/s/{}/rest/usergroup".format(self._baseurl, self._site, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE USERGROUP\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def create_wlan(self, name, x_passphrase, enabled, security, wep_idx,
                wpa_mode, wpa_enc, usergroup_id, dtim_mode, dtim_ng, dtim_na,
                minrate_ng_enabled, minrate_ng_advertising_rates, minrate_ng_data_rate_kbps,
                minrate_ng_cck_rates_enabled, minrate_na_enabled, minrate_na_advertising_rates,
                minrate_na_data_rate_kbps, mac_filter_enabled, mac_filter_policy, mac_filter_list,
                name_combine_enabled, bc_filter_enabled, bc_filter_list,
                group_rekey, vlan_enabled, wlangroup_id, radius_das_enabled, schedule,
                minrate_ng_mgmt_rate_kbps, minrate_na_mgmt_rate_kbps, minrate_ng_beacon_rate_kbps,
                minrate_na_beacon_rate_kbps, is_guest, vlan, hide_ssid
                ):
    """ Create a new WLAN
    :param name:                            Required
    :param x_passphrase:                    optional if security != open (default open)
    :param enabled:                         optional (default True)
    :param security:                        optional (default open)
    :param wep_idx:                         optional (default 1)
    :param wpa_mode:                        optional (default wpa2)
    :param wpa_enc:                         optional (default ccmp)
    :param usergroup_id:                    Required (is found using usergroup name)
    :param dtim_mode:                       optional (default default)
    :param dtim_ng:                         optional (default 1)
    :param dtim_na:                         optional (default 1)
    :param minrate_ng_enabled:              optional (default False)
    :param minrate_ng_advertising_rates:    optional (default False)
    :param minrate_ng_data_rate_kbps:       optional (default 1000)
    :param minrate_ng_cck_rates_enabled:    optional (default True)
    :param minrate_na_enabled:              optional (default False)
    :param minrate_na_advertising_rates:    optional (default False)
    :param minrate_na_data_rate_kbps:       optional (default 6000)
    :param mac_filter_enabled:              optional (default False)
    :param mac_filter_policy:               optional (default allow)
    :param mac_filter_list:                 optional (default [])
    :param name_combine_enabled:            optional (default True)
    :param bc_filter_enabled:               optional (default False)
    :param bc_filter_list:                  optional (default [])
    :param group_rekey:                     optional (default 3600)
    :param vlan_enabled:                    optional (default False)
    :param wlangroup_id:                    Required (is found using wlangroup name)
    :param radius_das_enabled:              optional (default False)
    :param schedule:                        optional (default [])
    :param minrate_ng_mgmt_rate_kbps:       optional (default 1000)
    :param minrate_na_mgmt_rate_kbps:       optional (default 6000)
    :param minrate_ng_beacon_rate_kbps:     optional (default 1000)
    :param minrate_na_beacon_rate_kbps:     optional (default 6000)
    :return: True or False and data
    """
    payload = {
        'enabled': enabled, 'security': security, 'wep_idx': wep_idx,
        'wpa_mode': wpa_mode, 'wpa_enc': wpa_enc, 'usergroup_id': usergroup_id,
        'dtim_mode': dtim_mode, 'dtim_ng': dtim_ng, 'dtim_na': dtim_na,
        'minrate_ng_enabled': minrate_ng_enabled, 'minrate_ng_advertising_rates': minrate_ng_advertising_rates,
        'minrate_ng_data_rate_kbps': minrate_ng_data_rate_kbps,
        'minrate_ng_cck_rates_enabled': minrate_ng_cck_rates_enabled, 'minrate_na_enabled': minrate_na_enabled,
        'minrate_na_advertising_rates': minrate_na_advertising_rates,
        'minrate_na_data_rate_kbps': minrate_na_data_rate_kbps, 'mac_filter_enabled': mac_filter_enabled,
        'mac_filter_policy': mac_filter_policy, 'mac_filter_list': mac_filter_list,
        'name_combine_enabled': name_combine_enabled, 'bc_filter_enabled': bc_filter_enabled,
        'bc_filter_list': bc_filter_list, 'group_rekey': group_rekey, 'name': name,
        'vlan_enabled': vlan_enabled, 'wlangroup_id': wlangroup_id, 'radius_das_enabled': radius_das_enabled,
        'schedule': schedule, 'minrate_ng_mgmt_rate_kbps': minrate_ng_mgmt_rate_kbps,
        'minrate_na_mgmt_rate_kbps': minrate_na_mgmt_rate_kbps,
        'minrate_ng_beacon_rate_kbps': minrate_ng_beacon_rate_kbps,
        'minrate_na_beacon_rate_kbps': minrate_na_beacon_rate_kbps,
    }
    if x_passphrase is not None and security != 'open':
        payload['x_passphrase'] = x_passphrase
    if is_guest:
        payload['is_guest'] = is_guest
    if vlan_enabled:
        payload['vlan'] = vlan
    if hide_ssid:
        payload['hide_ssid'] = hide_ssid


    payload = refactoring.dumps_loads(payload)
    # pprint.pprint(payload)
    logging.debug("\tPayload\n-------------------------------")
    logging.debug(str(payload) + "\n-------------------------------")

    resp = self._session.post("{}/api/s/{}/rest/wlanconf".format(self._baseurl, self._site, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE WLAN\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def update_wlan(self, payload):
    """ Change a WLAN
    :param payload:                         Required

    :return: True or False and data
    """

    if '_id' in payload:
        _id = payload['_id']
    else:
        logging.error("Did not find _id in payload, cannot change wlan config without it.")
        return False, []

    payload = refactoring.dumps_loads(payload)
    logging.debug("\tPayload\n-------------------------------")
    logging.debug(str(payload) + "\n-------------------------------")

    resp = self._session.put("{}/api/s/{}/rest/wlanconf/{}".format(self._baseurl, self._site, _id, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE WLAN\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def create_network(self, name, purpose, networkgroup, dhcpd_enabled, dhcpd_leasetime,
                   dhcpd_dns_enabled, dhcpd_gateway_enabled, dhcpd_time_offset_enabled,
                   ipv6_interface_type, ipv6_pd_start, ipv6_pd_stop, vlan,
                   ip_subnet, dhcpd_start, dhcpd_stop,
                   dhcpd_unifi_controller, enabled, is_nat, dhcp_relay_enabled,
                   vlan_enabled, domain_name):
    payload = {
        "purpose": purpose,
        "networkgroup": networkgroup,
        "dhcpd_enabled": dhcpd_enabled,
        "dhcpd_leasetime": dhcpd_leasetime,
        "dhcpd_dns_enabled": dhcpd_dns_enabled,
        "dhcpd_gateway_enabled": dhcpd_gateway_enabled,
        "dhcpd_time_offset_enabled": dhcpd_time_offset_enabled,
        "ipv6_interface_type": ipv6_interface_type,
        "ipv6_pd_start": ipv6_pd_start,
        "ipv6_pd_stop": ipv6_pd_stop,
        "name": name,
        "vlan": vlan,
        "ip_subnet": ip_subnet,
        "dhcpd_start": dhcpd_start,
        "dhcpd_stop": dhcpd_stop,
        "dhcpd_unifi_controller": dhcpd_unifi_controller,
        "enabled": enabled,
        "is_nat": is_nat,
        "dhcp_relay_enabled": dhcp_relay_enabled,
        "vlan_enabled": vlan_enabled,
        "domain_name": domain_name
    }
    payload = refactoring.dumps_loads(payload)
    resp = self._session.post("{}/api/s/{}/rest/networkconf".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % payload)
    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE NETWORK\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def invite_admin(self, name, email, enable_sso, readonly, device_adopt, device_restart):
    permissions = []
    payload = {"cmd": "invite-admin",
               "name": name,
               "email": email,
               "for_sso": enable_sso,
               "role": "admin"
               }

    if readonly:
        payload["role"] = "readonly"
    if device_adopt:
        permissions.append("API_DEVICE_ADOPT")
    if device_restart:
        permissions.append("API_DEVICE_RESTART")

    payload["permissions"] = permissions
    payload = refactoring.dumps(payload)

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              data="json=%s" % payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("CREATE WLAN\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def delete_site(self, siteID):
    payload = {'site': siteID, 'cmd': 'delete-site'}

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("DELETE SITE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def delete_wlanconf(self, wlanid):
    resp = self._session.delete("{}/api/s/{}/rest/wlanconf/{}".format(self._baseurl, self._site, wlanid),
                                verify=self._verify_ssl)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("DELETE WLAN\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def delete_usergroup(self, userid):
    resp = self._session.delete("{}/api/s/{}/rest/usergroup/{}".format(self._baseurl, self._site, userid),
                                verify=self._verify_ssl)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("DELETE WLAN\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def update_sitename(self, sitename):
    payload = {"desc": sitename, "cmd": "update-site"}

    resp = self._session.post("{}/api/s/{}/cmd/sitemgr".format(self._baseurl, self._site, verify=self._verify_ssl),
                              json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UPDATE SITENAME\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def update_mgmt(self, id, siteid, advFeat, mgmtkey, xssh, xsshuser, xsshpass, led):
    payload = {"_id": id,
               "site_id": siteid,
               "key": "mgmt",
               "advanced_feature_enabled": advFeat,
               "x_ssh_enabled": xssh,
               "x_ssh_bind_wildcard": False,
               "x_ssh_auth_password_enabled": True,
               "unifi_idp_enabled": True,
               "x_mgmt_key": mgmtkey,
               "x_ssh_username": xsshuser,
               "x_ssh_password": xsshpass,
               "led_enabled": led,
               "alert_enabled": False,
               "x_ssh_keys": []}

    resp = self._session.post("{}/api/s/{}/set/setting/mgmt/{}".format(self._baseurl, self._site, id,
                                                                       verify=self._verify_ssl), json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UPDATE MGMT\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def update_country(self, ccode, siteid):
    payload = {"key": "country",
               "code": ccode,
               "site_id": siteid}

    resp = self._session.post("{}/api/s/{}/set/setting/country".format(self._baseurl, self._site,
                                                                       verify=self._verify_ssl), json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UPDATE COUNTRY\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data


def update_locale(self, timezone, siteid):
    payload = {"key": "locale",
               "timezone": timezone,
               "site_id": siteid}

    resp = self._session.post("{}/api/s/{}/set/setting/locale".format(self._baseurl, self._site,
                                                                      verify=self._verify_ssl), json=payload)

    data = resp.json()['data']
    meta = resp.json()['meta']

    logging.debug("UPDATE LOCALE\n------------\nData: %s \nMeta: %s \n------------" % (data, meta))

    if meta['rc'] == 'ok':
        return True, data
    else:
        logging.error("Error message: " + meta['msg'])
        return False, data
