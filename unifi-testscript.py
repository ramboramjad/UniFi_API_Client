#!/usr/bin/env python3
from UniFi.UniFi import API
import logging
import argparse
import os
import time
from progress.bar import IncrementalBar


def ping(server):
    # function to do ping to entered server
    hostname = server
    response = os.system("ping " + hostname + " -c 1 > /dev/null 2>&1")
    if response == 0:
        return True
    return False


def start(api, bar):
    logging.info('LOGGING IN')
    if not api.login():
        logging.error('***    LOGGING IN FAILED    ***')
        logging.error('***        QUITTING         ***')
        exit(1)
    bar.next()
    logging.info('Checking Controller Status')
    if not api.status_controller():
        logging.error('***  CHECKING STATUS FAILED  ***')
        logging.error('***        QUITTING         ***')
        exit(1)
    bar.next()


def site_test(args, api, site, bar, server, create):
    logging.info('Running test on Sites')
    logging.debug('Creating new Site')
    if create:
        if not api.create_site(site):
            logging.error('*** FAILED TO CREATE NEW SITE ***')
            return False
        bar.next()
        logging.debug('Checking if new Site exists')
        succes, sites = api.list_sites()
        if succes:
            for i in sites:
                if i['desc'] == site:
                    logging.debug('Site exists. Creation was successful')
    if not create:
        succes, sites = api.list_sites()
        if succes:
            for i in sites:
                if i['desc'] == site:
                    siteid = i['name']
                    siteID = i['_id']
                    logging.debug('Site exists. Trying to remove it. ')
                    api2 = API(username=args.user, password=args.password, baseurl=server, site=siteid,
                               verify_ssl=False)
                    api2.login()
                    if api2.delete_site(siteID):
                        logging.debug('Removing test-site was successful')
                        api2.logout()
                    else:
                        logging.error('*** REMOVING TEST-SITE FAILED ***')
                    logging.info("Check on sites was successful")
                    return True
    return False


def WLAN(api, bar):
    logging.info('Running test on WLAN')
    logging.debug('Creating new WLAN')
    wlan = 'Testing Wi-Fi'
    if not api.create_wlan(name=wlan, security='wpapsk', x_passphrase='Generatedpass'):
        logging.error('*** FAILED TO CREATE NEW WLAN ***')
        return False
    bar.next()
    logging.debug('checking if new WLAN exists')
    succes, wlans = api.list_wlanconf()
    if succes:
        for i in wlans:
            if i['name'] == wlan:
                wlanid = i['_id']
                logging.debug('Removing newly made WLAN')
                if api.delete_wlanconf(wlanid):
                    logging.debug('Removing WLAN was successful')
                else:
                    logging.error('*** REMOVING WLAN FAILED ***')
                logging.info("Check on WLAN was successful")
                return True
    logging.error('*** CHECK ON WLAN FAILED ***')
    return False


def devices(args, api, site, bar, server):
    logging.info('Running test on devices')
    logging.debug('Fetching all devices')
    global siteID
    succes, devices = api.list_devices()
    if not succes:
        logging.error('*** FAILED TO FETCH DEVICES ***')
        return False
    bar.next()
    if not devices:
        logging.error('*** NO DEVICES FOUND ***')
        return False

    logging.debug('Checking if there are adoptable devices')
    for i in devices:
        if not i['adopted']:
            logging.debug('Found adoptable device:  %s model:       %s', i['mac'], i['model'])
            logging.debug('ADOPTING DEVICE MAC      %s AND MODEL    %s', i['mac'], i['model'])
            if not api.adopt_device(i['mac']):
                logging.error('*** FAILED TO ADOPT DEVICE ***')
                return False
    bar.next()
    logging.debug('SLEEPING for 60 sec (to finalize adoption)')
    time.sleep(60)
    succes, devices = api.list_devices()
    deviceID = devices[0]['_id']
    logging.debug('Renaming device')
    api.rename_device(deviceID, 'Generated-name')
    bar.next()
    succes, devices = api.list_devices()
    for i in devices:
        if i['_id'] == deviceID:
            if i['name'] == 'Generated-name':
                mac = i['mac']
                logging.debug('Renaming device successfull')
            else:
                logging.error('*** FAILED TO RENAME DEVICE ***')

    bar.next()
    siteID = ''
    logging.debug('Fetching sites for moving device')
    succes, sites = api.list_sites()
    if not succes:
        logging.error('*** FAILED TO FETCH SITES FOR MOVING ***')
        return False
    for i in sites:
        if i['desc'] == site:
            siteid = i['_id']
            siteID = i['name']
    if siteID == '':
        site_test(args, api, site, bar, server, True)
        succes, sites = api.list_sites()
        for i in sites:
            if i['desc'] == site:
                siteid = i['_id']
                siteID = i['name']

    bar.next()
    logging.debug('Moving device to another site (this may take a while)')
    logging.debug('Moving device')
    succes, data = api.move_device(mac, siteid)
    if not succes:
        logging.error('*** FAILED TO MOVE DEVICE ***')
        logging.debug('Deleting device without having moved it.')
        logging.debug('SLEEPING for 60 sec, waiting to finish provisioning')
        time.sleep(60)
        succes, data = api.delete_device(mac)
        if not succes:
            logging.error('*** FAILED TO DELETE DEVICE WITHOUT MOVING ***')
            return False
        site_test(args, api, site, bar, server, False)
        return False

    bar.next()
    logging.debug('Deleting device from other site (this may take a while)')
    logging.debug('SLEEPING for 60 sec, waiting to finish provisioning')
    time.sleep(60)
    api2 = API(username=args.user, password=args.password, baseurl=server, site=siteID, verify_ssl=False)
    api2.login()
    if not api2.delete_device(mac):
        logging.error('*** FAILED TO DELETE DEVICE ***')
        api2.logout()
        return False
    site_test(args, api, site, bar, server, False)
    logging.info("Check on Devices was successful")
    return True


def usergroup(api, bar):
    logging.info('Running test on Usergroups')
    logging.debug('Creating new Usergroup')
    if not api.create_usergroup('testgroup', 5000, 5000):
        logging.error('*** FAILED TO CREATE NEW USERGROUPS ***')
        return False

    bar.next()
    logging.debug('Listing all Usergroups')
    succes, usergroups = api.list_usergroup()
    if not succes:
        logging.error('*** FAILED TO FETCH USERGROUPS ***')
    for i in usergroups:
        if i['name'] == 'testgroup':
            userid = i['_id']
            logging.debug('Deleting newly created Usergroup')
            if api.delete_usergroup(userid):
                logging.info("Check on Usergroups was successful")
                return True
    return False


def simple(args, api, bar, server):
    # function for running simple test
    start(api, bar)
    site = 'Generated Site'
    site_test(args, api, site, bar, server, True)
    site_test(args, api, site, bar, server, False)
    bar.next()
    WLAN(api, bar)
    bar.next()
    devices(args, api, site, bar, server)


def full(args, api, bar, server):
    start(api, bar)
    site = 'Generated Site'
    bar.next()
    WLAN(api, bar)
    bar.next()
    devices(args, api, site, bar, server)
    bar.next()
    usergroup(api, bar)


def no_device(args, api, bar, server):
    start(api, bar)
    site = 'Generated Site'
    site_test(args, api, site, bar, server, True)
    site_test(args, api, site, bar, server, False)
    bar.next()
    usergroup(api, bar)
    bar.next()
    WLAN(api, bar)
    bar.next()


# parse all required/ available arguments
parser = argparse.ArgumentParser(prog='unifi_testscript', description='Testscript for functionally testing UniFi API '
                                                                      'CLient')
parser.add_argument(
    '-v', '--verbose', help="Set logging level to 'DEBUG'", action='store_true')
parser.add_argument(
    '-q', '--quiet', help="Runs quiet, only errors will be shown", action='store_true')
parser.add_argument(
    '--wlan', help='Test only WLAN functionality (very quick)', action='store_true')
parser.add_argument(
    '-s', '--simple', help='Test simple functionality like: WLAN, Sites, Adoption and moving (quick)',
    action='store_true')
parser.add_argument(
    '-f', '--full', help='Do a full test of all functions build in (extensive)', action='store_true')
parser.add_argument(
    '--no-device', help='Do a full test of all functions build in except for functions that use a device',
    action='store_true')
parser.add_argument(
    '-S', '--Server', type=str, help="Enter hostname or IP for running UniFi controller. Default is "
                                     "'localhost'", default='localhost')
parser.add_argument(
    '-u', '--user', type=str, help="Enter username for UniFi controller. Default is 'ubnt'",
    default='ubnt')
parser.add_argument(
    '-p', '--password', type=str, help="Enter password for UniFi controller. Default is 'ubnt'",
    default='ubnt')
args = parser.parse_args()

if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
elif args.quiet:
    logging.basicConfig(level=logging.ERROR)
else:
    logging.basicConfig(level=logging.INFO)

server = args.Server
if not ping(server):
    logging.error('*** NO CONNECTION TO UNIFI CONTROLLER ***')
    logging.error('***        QUITTING         ***')
    exit(1)
server = 'https://' + server + ':8443'

api = API(username=args.user, password=args.password, baseurl=server, site="default", verify_ssl=False)

if args.simple:
    bar = IncrementalBar('Progress', max=13)
    simple(args, api, bar, server)
    bar.finish()
    logging.info('COMPLETED SIMPLE TEST')
elif args.wlan:
    bar = IncrementalBar('Progress', max=5)
    start(api, bar)
    WLAN(api, bar)
    bar.next()
    usergroup(api, bar)
    bar.finish()
    logging.info('COMPLETED WLAN TEST')
elif args.full:
    bar = IncrementalBar('Progress', max=15)
    full(args, api, bar, server)
    bar.finish()
    logging.info('COMPLETED FULL TEST')
elif args.no_device:
    bar = IncrementalBar('Progress', max=8)
    no_device(args, api, bar, server)
    bar.finish()
    logging.info('COMPLETED NO-DEVICE TEST')
else:
    logging.error('***    SOMETHING WENT WRONG    ***')
    logging.error('***        NO TEST RAN         ***')
    logging.error('*** DID YOU CHOOSE A TEST-TYPE ***')

# THINGS TO DO!
# ------------------------------------------
# reties instelbaar en time sleep instelbaar.
# config parser
#
# standard error weg pipen!!! dan wel still.
# crash van controller halverwege testen
# by default GEEN INFO ook geen progressbar.
# 	-v is info en -vv is debug
