import argparse
import datetime
import json
import logging
import os
import re
import uuid

import requests
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import LegacyApplicationClient
from oauthlib.oauth2.rfc6749 import tokens
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError

ODATA_FILTER_EXAMPLES = """
example ODATA filter queries:
  - startswith(Name,'S1A')
  - contains(Name,'MPL_ORBPRE')
  - ContentDate/Start gt 2023-01-01T00:00:00.000Z
  - PublicationDate gt 2023-01-01T00:00:00.000Z
  - Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'AUX_RESORB')
"""

logger = logging.getLogger(__name__)


class CSCIPSession:
    def __init__(self, id, config_path=None, timeout=60):
        self.timeout = timeout
        if config_path is None:
            config_path = os.getenv("CSCIP_CLIENT_CONFIG")
            if config_path is None:
                raise Exception("CSCIP_CLIENT_CONFIG environment variable is not set")
        config = json.loads(open(config_path).read())
        for service_url in config:
            if 'id' in config[service_url]:
                if config[service_url]['id'] == id:
                    self.service_url = service_url
                    self.credentials = config[service_url]
                    break
        else:
            raise Exception(f"service interface with id '{id}' not found")
        self.session = requests
        self.auth = None
        if 'auth_type' in self.credentials:
            if self.credentials['auth_type'] == "oauth2":
                if self.credentials['grant_type'] != "ResourceOwnerPasswordCredentialsGrant":
                    raise Exception(f"Unsupported oauth2 grant type {self.credentials['grant_type']}",)
                if self.service_url.startswith("http://"):
                    # if the credentials file explicitly mentions the HTTP protocol then allow insecure transport
                    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
                self.session = OAuth2Session(client=LegacyApplicationClient(client_id=self.credentials['client_id']))
                self.session.fetch_token(token_url=self.credentials['token_url'], username=self.credentials['username'],
                                         password=self.credentials['password'], client_id=self.credentials['client_id'],
                                         client_secret=self.credentials['client_secret'], timeout=self.timeout)
            else:
                raise Exception(f"Unsupported authentication type {self.credentials['auth_type']}",)
        elif 'username' in self.credentials:
            self.auth = requests.auth.HTTPBasicAuth(self.credentials['username'], self.credentials['password'])

    def get(self, url, allow_redirects=True, stream=False):
        try:
            return self.session.get(url, auth=self.auth, timeout=self.timeout, allow_redirects=allow_redirects,
                                    stream=stream)
        except TokenExpiredError:
            self.session.fetch_token(token_url=self.credentials['token_url'], username=self.credentials['username'],
                                     password=self.credentials['password'], client_id=self.credentials['client_id'],
                                     client_secret=self.credentials['client_secret'], timeout=self.timeout)
            return self.session.get(url, auth=self.auth, timeout=self.timeout, allow_redirects=allow_redirects,
                                    stream=stream)

    def query(self, uuid=None, name_part=None, order_by="", filter=None, limit=100, attributes=False):
        url = self.service_url + "Products"
        arguments = []
        if uuid is not None:
            url += f"({uuid})"
        else:
            if name_part is not None:
                if filter is not None:
                    arguments += [f"$filter=contains(Name,'{name_part}') and ({filter})"]
                else:
                    arguments += [f"$filter=contains(Name,'{name_part}')"]
            elif filter is not None:
                arguments += [f"$filter={filter}"]
            if order_by:
                if order_by[0] == "+":
                    arguments += [f"$orderby={order_by[1:]} asc"]
                else:
                    arguments += [f"$orderby={order_by} desc"]
            if limit:
                arguments += [f"$top={limit}"]
        if attributes:
            arguments += [f"$expand=Attributes"]
        if arguments:
            url += "?" + "&".join(arguments)

        try:
            resp = self.get(url, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            logger.debug("====REQUEST=====")
            logger.debug(f"url: {e.request.url}")
            logger.debug(f"headers: {e.request.headers}")
            logger.debug("================")
            logger.error(e)
            return None

        logger.debug("====REQUEST=====")
        logger.debug(f"url: {resp.request.url}")
        logger.debug(f"headers: {resp.request.headers}")
        logger.debug("====RESPONSE====")
        logger.debug(f"url: {resp.url}")
        logger.debug(f"headers: {resp.headers}")
        logger.debug(f"content: {resp.content}")
        logger.debug("================")
        resp.raise_for_status()

        result = json.loads(resp.content)

        if 'error' in result:
            logger.error(result['error']['message'])
            return None

        if uuid is not None:
            return [result]
        elif 'value' in result:
            return result['value']
        return None

    def download(self, entry, target_path=None):
        if target_path is None:
            target_path = os.getcwd()
        try:
            url = self.service_url + "Products(" + entry['Id'] + ")/$value"
            if 'reuse_auth_on_redirect' in self.credentials and self.credentials['reuse_auth_on_redirect']:
                resp = self.get(url, allow_redirects=False, stream=True)
                if resp.status_code == 301:
                    redirect_url = resp.headers['Location']
                    logger.debug(f"explicitly redirecting: {redirect_url}")
                    resp = self.get(redirect_url, allow_redirects=False, stream=True)
            else:
                resp = self.get(url, stream=True)
            resp.raise_for_status()
            local_file = os.path.join(target_path, entry['Name'])
            if 'content-disposition' in [key.lower() for key in resp.headers.keys()]:
                matches = re.findall("filename=\"?([^\"]+)\"?", resp.headers['content-disposition'])
                if len(matches) > 0:
                    filename = matches[-1]
                    if filename != entry['Name']:
                        logger.debug(f"downloaded file renamed from {entry['Name']} to {filename}")
                    local_file = os.path.join(target_path, filename)
            with open(local_file, 'wb') as fd:
                for chunk in resp.iter_content(chunk_size=1048576):  # use 1MB blocks
                    fd.write(chunk)
        except requests.exceptions.HTTPError as err:
            logger.error(f"HTTPError: {err}")


def main():
    global_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = global_parser.add_subparsers(title="subcommand", dest="subcommand")
    subparsers.required = True

    global_argument_parser = argparse.ArgumentParser(add_help=False)
    global_argument_parser.add_argument("-V", "--verbose", action="store_true", help="enable debug output")
    global_argument_parser.add_argument("-c", "--credentials", help="credentials file")
    global_argument_parser.add_argument("id", metavar="INTERFACE", help="identifier of CSC Interface delivery Point")

    query_argument_parser = argparse.ArgumentParser(add_help=False)
    group = query_argument_parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--uuid", help="query using uuid")
    group.add_argument("-n", "--name", help="query products containing given name fragment")
    query_argument_parser.add_argument("-o", "--order-by", default="PublicationDate",
                                       help="order result by the given field; a \"+\" prefix denotes ascending order; "
                                       "no prefix denotes descending order")
    query_argument_parser.add_argument("-f", "--filter", help="add custom ODATA filter")

    query_parser = subparsers.add_parser("query", parents=[global_argument_parser, query_argument_parser],
                                         formatter_class=argparse.RawDescriptionHelpFormatter,
                                         help="query api for entries", epilog=ODATA_FILTER_EXAMPLES)
    query_parser.add_argument("-l", "--limit", type=int, default=100,
                              help="maximum number of results to return (0 = unlimited)")
    query_parser.add_argument("-m", "--metadata", action="store_true", help="show all ODATA metadata for each item")
    query_parser.add_argument("-a", "--attributes", action="store_true", help="request attributes for each item")

    download_parser = subparsers.add_parser("download", parents=[global_argument_parser, query_argument_parser],
                                            formatter_class=argparse.RawDescriptionHelpFormatter,
                                            help="download products", epilog=ODATA_FILTER_EXAMPLES)
    download_parser.add_argument("-d", "--directory", help="directory in which retrieved products will be stored; "
                                 "by default, retrieved products will be stored in the current working directory")

    args = global_parser.parse_args()
    loglevel = logging.INFO
    if "verbose" in args:
        if args.verbose:
            loglevel = logging.DEBUG
    logging.basicConfig(level=loglevel, format="%(message)s")

    if args.subcommand == "query":
        odata_session = CSCIPSession(args.id, args.credentials)
        results = odata_session.query(uuid=args.uuid, name_part=args.name, filter=args.filter, order_by=args.order_by,
                                      limit=args.limit, attributes=args.attributes)
        if results is not None:
            for entry in results:
                items = [
                    entry['Id'],
                    entry['Name'],
                    entry['PublicationDate'],
                    str(entry['ContentLength']),
                ]
                if 'Online' in entry and not entry['Online']:
                    items.append("offline")
                logger.info(" ".join(items))
                if args.metadata:
                    logger.info(json.dumps(entry, indent=2))
    elif args.subcommand == "download":
        odata_session = CSCIPSession(args.id, args.credentials)
        results = odata_session.query(uuid=args.uuid, name_part=args.name, filter=args.filter, order_by=args.order_by,
                                      limit=0)
        if results is not None:
            for entry in results:
                logger.info(entry['Name'])
                odata_session.download(entry, args.directory)


if __name__ == '__main__':
    main()
