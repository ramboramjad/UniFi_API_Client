#!/usr/bin/python3
from UniFi.UniFi import API as Unifi_API
import logging
import pprint

# Set logging level
logging.basicConfig(level=logging.INFO)

# set controller information
api = Unifi_API(username="ubnt", password="ubnt", baseurl="https://unifi.ui:8443", site="default",
                verify_ssl=False)
# LOGIN
api.login()

# Show all devices within site
succes, device_list = api.list_devices()
print("Printing devices")
for device in device_list:
    print("Device with name: %30s and id: %20s " % (device["name"], device["_id"]))

# List all sites
succes, sites = api.list_sites()
print("Printing Sites")
for site in sites:
    pprint.pprint(site)

# Create a new site
sitename = 'GeneratedSite'
print("creating new Site")
if api.create_site(sitename):
    print("Site has been created")

# Create new Wlangroup
wlangroupName = '5bmlimit'
maxUp = 5000  # NOTE: Always in kb
maxDown = 5000  # NOTE: Always in kb
print("creating new usergroup")
if api.create_usergroup(wlangroupName, maxUp, maxDown):
    print("User group created.")

# list all Wlans configured in site
wlans = api.list_wlanconf()
pprint.pprint(wlans)

# Create new WLAN
wlanName = 'Generated Wi-Fi'
wlangroupName = '5bmlimit'
usergroup = 'Default'
password = 'Generatedpass'
print("Creating WLAN")
if api.create_wlan(wlanName, wlangroupName, usergroup, security="wpapsk", x_passphrase=password):
    print("WLAN created.")

# List adoptable devices
succes, devices = api.list_adoptable()
pprint.pprint(devices)

# List status of Controller
print(api.status_controller())

# move device to different site
deviceMAC = "xx:xx:xx:xx:xx:xx"
siteID = "xxxxxxxxxxxxxxxxxxxxxxxx"
print("Moving device %s to site %s", deviceMAC, siteID)
print(api.move_device(deviceMAC, siteID))

# Delete device
deviceMAC = "xx:xx:xx:xx:xx:xx"
api.delete_device(deviceMAC)

# LOGOUT
api.logout()
