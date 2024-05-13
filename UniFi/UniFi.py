#!/usr/bin/python3
from requests import Session
import requests
import json
from UniFi import list, devices, create, clients


class API(object):
    """ Unifi API for the Unifi Controller. """
    _login_data = {}
    _current_status_code = None

    def __init__(self, username: str = "ubnt", password: str = "ubnt", site: str = "default",
                 baseurl: str = "https://unifi:8443", verify_ssl: bool = False, unifios: bool = False):
        """ Initiates tha api with default settings if none other are set.
        :param username: username for the controller user
        :param password: password for the controller user
        :param site: which site to connect to (Not the name you've given the site, but the url-defined name)
        :param baseurl: where the controller is located
        :param verify_ssl: Check if certificate is valid or not, throws warning if set to False
        """
        self._login_data['username'] = username
        self._login_data['password'] = password
        self._site = site
        self._verify_ssl = verify_ssl
        if unifios:
            baseurl = baseurl + '/proxy/network'
        self._baseurl = baseurl
        self._session = Session()
        requests.packages.urllib3.disable_warnings()

    def login(self):
        """ Log the user in
        :return: None
        """
        self._current_status_code = self._session.post("{}/api/login".format(self._baseurl),
                                                       data=json.dumps(self._login_data),
                                                       verify=self._verify_ssl).status_code
        if self._current_status_code == 400:
            return False
        else:
            return True

    def logout(self):
        """ Log the user out
        :return: None
        """
        self._session.get("{}/logout".format(self._baseurl))
        self._session.close()

    def unauthorize_guest(self, mac):
        return clients.unauthorize_guest(self, mac)

    def authorize_guest(self, mac, min, up=None, down=None, limit=None, ap_mac=None):
        return clients.authorize_guest(self, mac, min, up, down, limit, ap_mac)

    def force_provision(self, mac):
        return devices.force_provision(self, mac)

    def adopt_device(self, mac):
        return devices.adopt_device(self, mac)

    def rename_device(self, ap_id, ap_name):
        return devices.rename_device(self, ap_id, ap_name)

    def delete_device(self, mac):
        return devices.delete_device(self, mac)

    def upgrade_device(self, mac):
        return devices.upgrade_device(self, mac)

    def move_device(self, mac, site_id):
        return devices.move_device(self, mac, site_id)

    def list_clients(self):
        return list.list_clients(self)

    def list_devices(self):
        return list.list_devices(self)

    def list_device(self, devserial):
        return list.list_device(self, devserial)

    def list_sites(self):
        return list.list_sites(self)

    def list_usergroup(self):
        return list.list_usergroup(self)

    def list_wlangroup(self):
        return list.list_wlangroup(self)

    def list_wlanconf(self, wlan_id=None):
        return list.list_wlanconf(self, wlan_id)

    def list_health(self):
        return list.list_health(self)

    def list_dashboard(self, five_minutes=False):
        return list.list_dashboard(self, five_minutes)

    def status_controller(self):
        return list.status_controller(self)

    def list_adoptable(self):
        return list.list_adoptable(self)

    def get_settings(self):
        return list.get_settings(self)

    def invite_admin(self, name, email, enable_sso=True, readonly=False, device_adopt=False, device_restart=False):
        return create.invite_admin(self, name, email, enable_sso, readonly, device_adopt, device_restart)

    def create_wlan(self, name, usergroup='Default', wlangroup='Default', x_passphrase=None, enabled=False,
                    security='open', wep_idx=1, wpa_mode='wpa2', wpa_enc='ccmp', usergroup_id='', dtim_mode='default',
                    dtim_ng=1, dtim_na=1, minrate_ng_enabled=False, minrate_ng_advertising_rates=False,
                    minrate_ng_data_rate_kbps=1000, minrate_ng_cck_rates_enabled=True, minrate_na_enabled=False,
                    minrate_na_advertising_rates=False, minrate_na_data_rate_kbps=6000, mac_filter_enabled=False,
                    mac_filter_policy='allow', mac_filter_list=[], name_combine_enabled=True, bc_filter_enabled=False,
                    bc_filter_list=[], group_rekey=3600, vlan_enabled=False, wlangroup_id='', radius_das_enabled=False,
                    schedule=[], minrate_ng_mgmt_rate_kbps=1000, minrate_na_mgmt_rate_kbps=6000,
                    minrate_ng_beacon_rate_kbps=1000, minrate_na_beacon_rate_kbps=6000, is_guest=False, vlan=None,
                    hide_ssid=False):

        succes1, users = API.list_usergroup(self)
        succes2, groups = API.list_wlangroup(self)
        for user in users:
            if user['name'] == usergroup:
                usergroup_id = user['_id']
        for wlan in groups:
            if wlan['name'] == wlangroup:
                wlangroup_id = wlan['_id']

        return create.create_wlan(self, name, x_passphrase, enabled,
                                  security, wep_idx, wpa_mode, wpa_enc, usergroup_id, dtim_mode,
                                  dtim_ng, dtim_na, minrate_ng_enabled, minrate_ng_advertising_rates,
                                  minrate_ng_data_rate_kbps, minrate_ng_cck_rates_enabled, minrate_na_enabled,
                                  minrate_na_advertising_rates, minrate_na_data_rate_kbps, mac_filter_enabled,
                                  mac_filter_policy, mac_filter_list, name_combine_enabled, bc_filter_enabled,
                                  bc_filter_list, group_rekey, vlan_enabled, wlangroup_id, radius_das_enabled,
                                  schedule, minrate_ng_mgmt_rate_kbps, minrate_na_mgmt_rate_kbps,
                                  minrate_ng_beacon_rate_kbps, minrate_na_beacon_rate_kbps, is_guest, vlan, hide_ssid)

    def create_site(self, descrioption):
        return create.create_site(self, descrioption)

    def create_usergroup(self, group_name, group_dn=-1, group_up=-1):
        return create.create_usergroup(self, group_name, group_dn, group_up)

    def create_network(self, name="LAN", purpose="corporate", networkgroup="LAN", dhcpd_enabled=True,
                       dhcpd_leasetime=86400,
                       dhcpd_dns_enabled=False, dhcpd_gateway_enabled=False, dhcpd_time_offset_enabled=False,
                       ipv6_interface_type=None, ipv6_pd_start="::2", ipv6_pd_stop="::7d1", vlan=None,
                       ip_subnet="192.168.10.1/24", dhcpd_start="192.168.10.1", dhcpd_stop="192.168.10.254",
                       dhcpd_unifi_controller="unifi", enabled=True, is_nat=True, dhcp_relay_enabled=False,
                       vlan_enabled=False, domain_name="localdomain"):
        return create.create_network(self, name, purpose, networkgroup, dhcpd_enabled, dhcpd_leasetime,
                                     dhcpd_dns_enabled, dhcpd_gateway_enabled, dhcpd_time_offset_enabled,
                                     ipv6_interface_type, ipv6_pd_start, ipv6_pd_stop, vlan,
                                     ip_subnet, dhcpd_start, dhcpd_stop,
                                     dhcpd_unifi_controller, enabled, is_nat, dhcp_relay_enabled,
                                     vlan_enabled, domain_name)

    def init_controller(self, admin="Netco", admin_email="engineers@netco.nl", admin_password="Netco123",
                        site_name="Cxx-Netco", country="NL", timezone="Europe/Amsterdam",
                        network_optimization=True, autobackup_enabled=True):
        if API.status_controller(self)[0]:
            return create.init_controller(self, admin, admin_email, admin_password, site_name, country, timezone,
                                          network_optimization, autobackup_enabled)
        else:
            return API.status_controller(self)

    def delete_site(self, siteID):
        return create.delete_site(self, siteID)

    def delete_wlanconf(self, wlanid):
        return create.delete_wlanconf(self, wlanid)

    def delete_usergroup(self, userid):
        return create.delete_usergroup(self, userid)

    def add_tag(self, mac, tag):
        return devices.add_tag(self, mac, tag)

    def add_snmp(self, devid, snmp):
        return devices.add_snmp(self, devid, snmp)

    def update_sitename(self, sitename):
        return create.update_sitename(self, sitename)

    def update_wlan(self, payload):
        return create.update_wlan(self, payload)
    def list_settings(self):
        return list.list_settings(self)

    def list_ccode(self):
        return list.list_ccode(self)

    def update_mgmt(self, id, siteid, xssh, xsshuser, xsshpass, mgmtkey, advFeat=False, led=False):
        return create.update_mgmt(self, id, siteid, advFeat, mgmtkey, xssh, xsshuser, xsshpass, led)

    def update_country(self, ccode, siteid):
        return create.update_country(self, ccode, siteid)

    def update_locale(self, timezone, siteid):
        return create.update_locale(self, timezone, siteid)

    def testing(self):
        return list.testing(self)
        
    
    # states:
    # 0 = Disconnected
    # 1 = Connected (ready)
    # 2 = pending adoption
    # 5 = provisioning
    # 7 = adopting
