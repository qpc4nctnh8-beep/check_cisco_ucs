#!/usr/bin/env python3
"""
check_cisco_ucs.py
Version 0.11 (converted from Go to Python)

check_cisco_ucs is a Nagios plugin to monitor Cisco UCS rack and blade center hardware.

This nagios plugin is free software, and comes with ABSOLUTELY NO WARRANTY.
It may be used, redistributed and/or modified under the terms of the GNU
General Public Licence (see http://www.fsf.org/licensing/licenses/gpl.txt).

See README.md and comments in original Go version for usage examples.
"""

import argparse
import logging
import re
import ssl
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from xml.dom import minidom

# Nagios exit codes
NAGIOS_OK = 0
NAGIOS_CRITICAL = 2
NAGIOS_UNKNOWN = 3

VERSION = "0.11"
MAX_NUM_ATTRIB = 10


def setup_logging(debug_level):
    """Configure logging based on debug level."""
    if debug_level >= 1:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL
    
    logging.basicConfig(
        level=level,
        format='%(message)s',
        stream=sys.stdout
    )
    return logging.getLogger(__name__)


def create_ssl_context(max_tls_version="1.1"):
    """Create SSL context with specified TLS version."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    if max_tls_version == "1.2":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif max_tls_version == "1.3":
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    
    return context


def xml_request(url, xml_data, ssl_context):
    """Send XML request and return response."""
    try:
        req = Request(
            url,
            data=xml_data.encode('utf-8'),
            headers={'Content-Type': 'text/xml'}
        )
        with urlopen(req, context=ssl_context) as response:
            return response.read().decode('utf-8')
    except Exception as e:
        raise Exception(f"HTTP request failed: {e}")


def build_aaaLogin_xml(username, password):
    """Build XML for login request."""
    root = ET.Element('aaaLogin')
    root.set('inName', username)
    root.set('inPassword', password)
    return ET.tostring(root, encoding='unicode')


def build_configResolveClass_xml(cookie, in_hierarchical, class_id, in_filter=None):
    """Build XML for class resolution request."""
    root = ET.Element('configResolveClass')
    root.set('cookie', cookie)
    root.set('inHierarchical', in_hierarchical)
    root.set('classId', class_id)
    
    if in_filter:
        filter_elem = ET.SubElement(root, 'inFilter')
        filter_type, class_name, property_name, value = in_filter
        
        filter_tag = ET.SubElement(filter_elem, filter_type)
        filter_tag.set('class', class_name)
        filter_tag.set('property', property_name)
        filter_tag.set('value', value)
    
    xml_str = ET.tostring(root, encoding='unicode')
    # Fix self-closing tags for compatibility
    xml_str = re.sub(r'></(\w+)>', r' />', xml_str)
    return xml_str


def build_configResolveDn_xml(cookie, in_hierarchical, dn):
    """Build XML for DN resolution request."""
    root = ET.Element('configResolveDn')
    root.set('cookie', cookie)
    root.set('inHierarchical', in_hierarchical)
    root.set('dn', dn)
    return ET.tostring(root, encoding='unicode')


def build_aaaLogout_xml(cookie):
    """Build XML for logout request."""
    root = ET.Element('aaaLogout')
    root.set('inCookie', cookie)
    return ET.tostring(root, encoding='unicode')


def parse_login_response(xml_response):
    """Parse login response and extract cookie and error info."""
    try:
        root = ET.fromstring(xml_response)
        cookie = root.get('outCookie', '')
        error_code = int(root.get('errorCode', '0'))
        error_descr = root.get('errorDescr', '')
        return cookie, error_code, error_descr
    except ET.ParseError as e:
        raise Exception(f"Failed to parse login response: {e}")


def get_xml_attributes(xml_data, element_name, attributes):
    """Extract attributes from XML elements."""
    results = []
    counter = 0
    
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        logging.debug(f"XML parse error: {e}")
        return results, counter
    
    # Find all matching elements
    for elem in root.iter(element_name):
        counter += 1
        values = []
        for attr in attributes:
            value = elem.get(attr, '')
            values.append(value)
        results.append(','.join(values))
    
    return results, counter


def logout(url, cookie, ssl_context, logger):
    """Send logout request."""
    try:
        xml_data = build_aaaLogout_xml(cookie)
        logger.debug(f"logout request: {xml_data}")
        response = xml_request(url, xml_data, ssl_context)
        logger.debug(f"logout response: {response}")
    except Exception as e:
        logger.warning(f"Logout failed: {e}")


def find_index(value, lst):
    """Find index of value in list, return -1 if not found."""
    try:
        return lst.index(value)
    except ValueError:
        return -1


def parse_property_filter(property_filter):
    """Parse property filter string into components."""
    parts = property_filter.split(':')
    if len(parts) != 3:
        raise ValueError("Property filter must be in format: type:property:value")
    return parts


def main():
    parser = argparse.ArgumentParser(
        description='Nagios plugin to monitor Cisco UCS via XML API',
        epilog='For usage examples, see README.md'
    )
    
    parser.add_argument('-H', '--host', required=True, 
                        help='UCS Manager IP address or CIMC IP address')
    parser.add_argument('-t', '--query-type', default='class', choices=['class', 'dn'],
                        help="Query type 'class' or 'dn' (default: class)")
    parser.add_argument('-q', '--query', default='storageLocalDisk',
                        help='XML API object class or DN (default: storageLocalDisk)')
    parser.add_argument('-o', '--object', default='',
                        help='XML API object class name')
    parser.add_argument('-s', '--hierarchical', default='false', choices=['true', 'false'],
                        help='Return child objects (default: false)')
    parser.add_argument('-a', '--attributes', default='id name',
                        help='Space-separated list of XML attributes (default: "id name")')
    parser.add_argument('-e', '--expect', default='Optimal',
                        help='Expect string (regex supported)')
    parser.add_argument('-u', '--username', required=True,
                        help='XML API username')
    parser.add_argument('-p', '--password', required=True,
                        help='XML API password')
    parser.add_argument('-d', '--debug', type=int, default=0,
                        help='Debug level: 1=errors, 2=warnings, 3=info')
    parser.add_argument('-E', '--show-env', action='store_true',
                        help='Print environment variables')
    parser.add_argument('-V', '--version', action='store_true',
                        help='Print plugin version')
    parser.add_argument('-z', '--zero-ok', action='store_true',
                        help='OK if zero instances found')
    parser.add_argument('-F', '--faults-only', action='store_true',
                        help='Display only faults in output')
    parser.add_argument('-M', '--tls-version', default='1.1', choices=['1.1', '1.2', '1.3'],
                        help='Max TLS version (default: 1.1)')
    parser.add_argument('-f', '--filter', default='',
                        help='Property filter: type:property:value')
    parser.add_argument('-P', '--proxy', default='',
                        help='Proxy URL')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.debug)
    
    # Handle version flag
    if args.version:
        print(f"{Path(sys.argv[0]).name} version: {VERSION}")
        sys.exit(0)
    
    # Handle environment flag
    if args.show_env:
        import os
        print("** environment variables start **")
        for key, value in os.environ.items():
            print(f"{key}={value}")
        print("** environment variables end **")
    
    # Parse attributes
    attribute_array = args.attributes.split()
    attribute_descr = ','.join(attribute_array)
    
    if len(attribute_array) > MAX_NUM_ATTRIB:
        print(f"UNKNOWN - maximum number of attributes is {MAX_NUM_ATTRIB}")
        sys.exit(NAGIOS_UNKNOWN)
    
    # Determine query class/dn
    if args.query_type == 'class':
        query_class = args.query
        query_dn = None
        logger.debug(f"query type: class ({query_class})")
    else:  # dn
        query_dn = args.query
        query_class = args.object
        logger.debug(f"query type: dn ({query_dn})")
    
    logger.debug(f"ip addr: {args.host} query: {args.query}")
    logger.debug(f"hierarchical: {args.hierarchical} attributes: {args.attributes} expect: {args.expect}")
    
    # Create SSL context
    ssl_context = create_ssl_context(args.tls_version)
    
    # Build login XML
    url = f"https://{args.host}/nuova"
    login_xml = build_aaaLogin_xml(args.username, args.password)
    
    logger.debug(f"url: {url}")
    logger.debug(f"login request: {login_xml}")
    
    # Login
    try:
        login_response = xml_request(url, login_xml, ssl_context)
    except Exception as e:
        print(f"UNKNOWN - Login failed: {e}")
        sys.exit(NAGIOS_UNKNOWN)
    
    logger.debug(f"login response: {login_response}")
    
    try:
        cookie, error_code, error_descr = parse_login_response(login_response)
    except Exception as e:
        print(f"UNKNOWN - Failed to parse login response: {e}")
        sys.exit(NAGIOS_UNKNOWN)
    
    if error_code != 0:
        print(f"UNKNOWN - aaaLogin Error: {error_descr} ({error_code})")
        sys.exit(NAGIOS_UNKNOWN)
    
    logger.debug(f"login cookie: {cookie}")
    
    # Perform query
    try:
        if args.query_type == 'class':
            # Parse property filter if provided
            in_filter = None
            if args.filter:
                filter_parts = parse_property_filter(args.filter)
                in_filter = tuple(filter_parts)
                logger.debug(f"propertyFilter: {in_filter}")
            
            query_xml = build_configResolveClass_xml(
                cookie, args.hierarchical, query_class, in_filter
            )
            logger.debug(f"configResolveClass request:\n{query_xml}")
            query_response = xml_request(url, query_xml, ssl_context)
        else:  # dn
            query_xml = build_configResolveDn_xml(cookie, args.hierarchical, query_dn)
            logger.debug(f"configResolveDn request: {query_xml}")
            query_response = xml_request(url, query_xml, ssl_context)
        
        logger.debug(f"query response: {query_response}")
    except Exception as e:
        print(f"UNKNOWN - Query failed: {e}")
        logout(url, cookie, ssl_context, logger)
        sys.exit(NAGIOS_UNKNOWN)
    
    # Logout
    logout(url, cookie, ssl_context, logger)
    
    # Parse response and extract attributes
    results, num_found_total = get_xml_attributes(query_response, query_class, attribute_array)
    logger.debug(f"results: {results} counter: {num_found_total}")
    
    # Build output
    output = f"Cisco UCS {args.query} ({attribute_descr})"
    
    # Match results against expect pattern
    num_found = 0
    expect_pattern = re.compile(args.expect)
    
    logger.debug(f"\n{results}\n")
    for val in results:
        matches = expect_pattern.findall(val)
        if matches:
            num_found += 1
        
        logger.debug(f"{val} num_found={num_found} total={num_found_total}")
        
        if num_found_total == 0 and args.faults_only:
            output += "\n" + val
        elif num_found_total == 1 and not args.faults_only:
            output += " " + val
        elif not args.faults_only:
            output += "\n" + val
    
    # Determine status
    if (args.zero_ok and num_found == 0 and num_found_total == 0) or \
       (num_found_total > 0 and num_found == num_found_total):
        status = "OK"
        exit_code = NAGIOS_OK
    else:
        status = "CRIT"
        exit_code = NAGIOS_CRITICAL
    
    print(f"{status} - {output} ({num_found} of {num_found_total} ok)")
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
