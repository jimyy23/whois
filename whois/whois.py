# -*- coding: utf-8 -*-

"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2010 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
from __future__ import annotations
import logging
import optparse
import os
import re
import socket
import sys
from typing import Optional, Pattern

logger = logging.getLogger(__name__)


class NICClient:
    ABUSEHOST = "whois.abuse.net"
    AI_HOST = "whois.nic.ai"
    ANICHOST = "whois.arin.net"
    APP_HOST = "whois.nic.google"
    AR_HOST = "whois.nic.ar"
    BNICHOST = "whois.registro.br"
    BW_HOST = "whois.nic.net.bw"
    BY_HOST = "whois.cctld.by"
    CA_HOST = "whois.ca.fury.ca"
    CHAT_HOST = "whois.nic.chat"
    CL_HOST = "whois.nic.cl"
    CM_HOST = "whois.netcom.cm"
    CR_HOST = "whois.nic.cr"
    DEFAULT_PORT = "nicname"
    DENICHOST = "whois.denic.de"
    DEV_HOST = "whois.nic.google"
    DE_HOST = "whois.denic.de"
    DK_HOST = "whois.dk-hostmaster.dk"
    DNICHOST = "whois.nic.mil"
    DO_HOST = "whois.nic.do"
    GAMES_HOST = "whois.nic.games"
    GNICHOST = "whois.nic.gov"
    GOOGLE_HOST = "whois.nic.google"
    GROUP_HOST = "whois.namecheap.com"
    HK_HOST = "whois.hkirc.hk"
    HN_HOST = "whois.nic.hn"
    HR_HOST = "whois.dns.hr"
    IANAHOST = "whois.iana.org"
    INICHOST = "whois.networksolutions.com"
    IST_HOST = "whois.afilias-srs.net"
    JOBS_HOST = "whois.nic.jobs"
    JP_HOST = "whois.jprs.jp"
    KZ_HOST = "whois.nic.kz"
    LAT_HOST = "whois.nic.lat"
    LI_HOST = "whois.nic.li"
    LIVE_HOST = "whois.nic.live"
    LNICHOST = "whois.lacnic.net"
    LT_HOST = "whois.domreg.lt"
    MARKET_HOST = "whois.nic.market"
    MNICHOST = "whois.ra.net"
    MONEY_HOST = "whois.nic.money"
    MX_HOST = "whois.mx"
    NICHOST = "whois.crsnic.net"
    NL_HOST = "whois.domain-registry.nl"
    NORIDHOST = "whois.norid.no"
    ONLINE_HOST = "whois.nic.online"
    OOO_HOST = "whois.nic.ooo"
    PAGE_HOST = "whois.nic.page"
    PANDIHOST = "whois.pandi.or.id"
    PE_HOST = "kero.yachay.pe"
    PNICHOST = "whois.apnic.net"
    QNICHOST_TAIL = ".whois-servers.net"
    QNICHOST_HEAD = "whois.nic."
    RNICHOST = "whois.ripe.net"
    SNICHOST = "whois.6bone.net"
    WEBSITE_HOST = "whois.nic.website"
    ZA_HOST = "whois.registry.net.za"
    RU_HOST = "whois.tcinet.ru"
    IDS_HOST = "whois.identitydigital.services"
    GDD_HOST = "whois.dnrs.godaddy"
    SHOP_HOST = "whois.nic.shop"
    SG_HOST = "whois.sgnic.sg"
    STORE_HOST = "whois.centralnic.com"
    STUDIO_HOST = "whois.nic.studio"
    DETI_HOST = "whois.nic.xn--d1acj3b"
    MOSKVA_HOST = "whois.registry.nic.xn--80adxhks"
    RF_HOST = "whois.registry.tcinet.ru"
    PIR_HOST = "whois.publicinterestregistry.org"
    NG_HOST = "whois.nic.net.ng"
    PPUA_HOST = "whois.pp.ua"
    UKR_HOST = "whois.dotukr.com"
    TN_HOST = "whois.ati.tn"
    SBS_HOST = "whois.nic.sbs"
    GA_HOST = "whois.nic.ga"
    XYZ_HOST = "whois.nic.xyz"

    SITE_HOST = "whois.nic.site"
    DESIGN_HOST = "whois.nic.design"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois: list[str] = [LNICHOST, RNICHOST, PNICHOST, BNICHOST, PANDIHOST]

    def __init__(self, prefer_ipv6: bool = False):
        self.use_qnichost: bool = False
        self.prefer_ipv6 = prefer_ipv6

    @staticmethod
    def findwhois_server(buf: str, hostname: str, query: str) -> Optional[str]:
        """Search the initial TLD lookup results for the regional-specific
        whois server for getting contact details.
        """
        nhost = None
        match = re.compile(
            r"Domain Name: {}\s*.*?Whois Server: (.*?)\s".format(query),
            flags=re.IGNORECASE | re.DOTALL,
        ).search(buf)
        if match:
            nhost = match.group(1)
            # if the whois address is domain.tld/something then
            # s.connect((hostname, 43)) does not work
            if nhost.count("/") > 0:
                nhost = None
        elif hostname == NICClient.ANICHOST:
            for nichost in NICClient.ip_whois:
                if buf.find(nichost) != -1:
                    nhost = nichost
                    break
        return nhost

    @staticmethod
    def get_socks_socket():
        try:
            import socks
        except ImportError as e:
            logger.error(
                "You need to install the Python socks module. Install PIP "
                "(https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'"
            )
            raise e
        socks_user, socks_password = None, None
        if "@" in os.environ["SOCKS"]:
            creds, proxy = os.environ["SOCKS"].split("@")
            socks_user, socks_password = creds.split(":")
        else:
            proxy = os.environ["SOCKS"]
        socksproxy, port = proxy.split(":")
        socks_proto = socket.AF_INET
        if socket.AF_INET6 in [
            sock[0] for sock in socket.getaddrinfo(socksproxy, port)
        ]:
            socks_proto = socket.AF_INET6
        s = socks.socksocket(socks_proto)
        s.set_proxy(
            socks.SOCKS5, socksproxy, int(port), True, socks_user, socks_password
        )
        return s

    def _connect(self, hostname: str, timeout: int) -> socket.socket:
        """Resolve WHOIS IP address and connect to its TCP 43 port."""
        port = 43

        if "SOCKS" in os.environ:
            s = NICClient.get_socks_socket()
            s.settimeout(timeout)
            s.connect((hostname, port))
            return s

        # Resolve all IP addresses for the WHOIS server
        addr_infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

        if self.prefer_ipv6:
            # Sort by family to prioritize AF_INET6 (10) over AF_INET (2)
            addr_infos.sort(key=lambda x: x[0], reverse=True)

        last_err = None
        # Attempt to connect to each related IP address until one works
        for family, sock_type, proto, __, sockaddr in addr_infos:
            s = None
            try:
                s = socket.socket(family, sock_type, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
                return s
            except socket.error as e:
                last_err = e
                if s:
                    s.close()
                continue

        raise last_err or socket.error(f"Could not connect to {hostname}")

    def findwhois_iana(self, tld: str, timeout: int = 10) -> Optional[str]:
        s = self._connect("whois.iana.org", timeout)
        s.send(bytes(tld, "utf-8") + b"\r\n")
        response = b""
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        match = re.search(r"whois:[ \t]+(.*?)\n", response.decode("utf-8"))
        if match and match.group(1):
            return match.group(1)
        else:
            return None

    def whois(
        self,
        query: str,
        hostname: str,
        flags: int,
        many_results: bool = False,
        quiet: bool = False,
        timeout: int = 10,
        ignore_socket_errors: bool = True
    ) -> str:
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specific whois server and do a lookup
        there for contact details.  If `quiet` is `True`, will
        not send a message to logger when a socket error
        is encountered. Uses `timeout` as a number of seconds
        to set as a timeout on the socket. If `ignore_socket_errors`
        is `False`, will raise an exception instead of returning
        a string containing the error.
        """
        response = b""
        s = None
        try:  # socket.connect in a try, in order to allow things like looping whois on different domains without
            # stopping on timeouts: https://stackoverflow.com/questions/25447803/python-socket-connection-exception
            s = self._connect(hostname, timeout)
            if hostname == NICClient.DENICHOST:
                query_bytes = "-T dn,ace -C UTF-8 " + query
            elif hostname == NICClient.DK_HOST:
                query_bytes = " --show-handles " + query
            elif hostname.endswith(".jp"):
                query_bytes = query + "/e"
            elif hostname.endswith(NICClient.QNICHOST_TAIL) and many_results:
                query_bytes = "=" + query
            else:
                query_bytes = query
            s.send(bytes(query_bytes, "utf-8") + b"\r\n")
            # recv returns bytes
            while True:
                d = s.recv(4096)
                response += d
                if not d:
                    break

            nhost = None
            response_str = response.decode("utf-8", "replace")
            if 'with "=xxx"' in response_str:
                return self.whois(query, hostname, flags, True, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
            if flags & NICClient.WHOIS_RECURSE and nhost is None:
                nhost = self.findwhois_server(response_str, hostname, query)
            if nhost is not None and nhost != "":
                response_str += self.whois(query, nhost, 0, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
        except socket.error as e:
            if not quiet:
                logger.error(
                    "Error trying to connect to socket: closing socket - {}".format(e)
                )
            if ignore_socket_errors:
                # 'response' is assigned a value (also a str) even on socket timeout
                response_str = "Socket not responding: {}".format(e)
            else:
                raise e
        finally:
            if s:
                s.close()
        return response_str

    def choose_server(self, domain: str, timeout: int = 10) -> Optional[str]:
        """Choose initial lookup NIC host"""
        domain = domain.encode("idna").decode("utf-8")
        if domain.endswith("-NORID"):
            return NICClient.NORIDHOST
        if domain.endswith(".id"):
            return NICClient.PANDIHOST
        if domain.endswith(".hr"):
            return NICClient.HR_HOST
        if domain.endswith(".pp.ua"):
            return NICClient.PPUA_HOST
        if domain.endswith(
            (
                ".ae.org",
                ".br.com",
                ".cn.com",
                ".co.com",
                ".co.ro",
                ".com.de",
                ".com.se",
                ".de.com",
                ".eu.com",
                ".gb.net",
                ".gr.com",
                ".hu.net",
                ".jp.net",
                ".jpn.com",
                ".mex.com",
                ".radio.am",
                ".radio.fm",
                ".ru.com",
                ".sa.com",
                ".se.net",
                ".shop.ro",
                ".uk.com",
                ".uk.net",
                ".us.com",
                ".us.org",
                ".za.bz",
                ".za.com",
            )
        ):
            return 'whois.centralnic.com'
        if domain.endswith(
            (
                ".bir.ru",
                ".cbg.ru",
                ".com.ru",
                ".msk.ru",
                ".msk.su",
                ".nov.ru",
                ".nov.su",
                ".ru.net",
                ".spb.ru",
                ".spb.su",
            )
        ):
            return 'whois.flexireg.net'
        if domain.endswith(
            (
                ".co.uz",
                ".com.uz",
                ".net.uz",
                ".org.uz",
            )
        ):
            return 'whois.reg.uz'
        if domain.endswith(
            (
                ".hk.com",
                ".hk.org",
                ".inc.hk",
                ".ltd.hk",
            )
        ):
            return 'whois.registry.hk.com'
        if domain.endswith(
            (
                ".net.ru",
                ".org.ru",
                ".pp.ru",
            )
        ):
            return 'whois.nic.net.ru'
        if domain.endswith(
            (
                ".za.net",
                ".za.org",
            )
        ):
            return 'whois.za.net'
        if domain.endswith(".ac.uk"):
            return 'whois.ac.uk'
        if domain.endswith(".biz.ua"):
            return 'whois.biz.ua'
        if domain.endswith(".co.ca"):
            return 'whois.co.ca'
        if domain.endswith(".co.nl"):
            return 'whois.co.nl'
        if domain.endswith(".co.no"):
            return 'whois.co.no'
        if domain.endswith(".co.pl"):
            return 'whois.co.pl'
        if domain.endswith(".co.ua"):
            return 'whois.co.ua'
        if domain.endswith(".ac.ru"):
            return 'whois.free.net'
        if domain.endswith(".it.com"):
            return 'whois.it.com'
        if domain.endswith(".ngo.us"):
            return 'whois.ngo.us'
        if domain.endswith(".v.ua"):
            return 'whois.v.ua'
        if domain.endswith(".nyc.mn"):
            return 'whois43.publiczone.org'

        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            return None
        tld = domain_parts[-1]
        if tld[0].isdigit():
            return NICClient.ANICHOST
        elif tld == "ai":
            return NICClient.AI_HOST
        elif tld == "app":
            return NICClient.APP_HOST
        elif tld == "ar":
            return NICClient.AR_HOST
        elif tld == "bw":
            return NICClient.BW_HOST
        elif tld == "by":
            return NICClient.BY_HOST
        elif tld == "ca":
            return NICClient.CA_HOST
        elif tld == "chat":
            return NICClient.CHAT_HOST
        elif tld == "cl":
            return NICClient.CL_HOST
        elif tld == "cm":
            return NICClient.CM_HOST
        elif tld == "cr":
            return NICClient.CR_HOST
        elif tld == "de":
            return NICClient.DE_HOST
        elif tld == "dev":
            return NICClient.DEV_HOST
        elif tld == "dk":
            return NICClient.DK_HOST
        elif tld == "do":
            return NICClient.DO_HOST
        elif tld == "games":
            return NICClient.GAMES_HOST
        elif tld == "goog" or tld == "google":
            return NICClient.GOOGLE_HOST
        elif tld == "group":
            return NICClient.GROUP_HOST
        elif tld == "hk":
            return NICClient.HK_HOST
        elif tld == "hn":
            return NICClient.HN_HOST
        elif tld == "ist":
            return NICClient.IST_HOST
        elif tld == "jobs":
            return NICClient.JOBS_HOST
        elif tld == "jp":
            return NICClient.JP_HOST
        elif tld == "kz":
            return NICClient.KZ_HOST
        elif tld == "lat":
            return NICClient.LAT_HOST
        elif tld == "li":
            return NICClient.LI_HOST
        elif tld == "live":
            return NICClient.LIVE_HOST
        elif tld == "lt":
            return NICClient.LT_HOST
        elif tld == "market":
            return NICClient.MARKET_HOST
        elif tld == "money":
            return NICClient.MONEY_HOST
        elif tld == "mx":
            return NICClient.MX_HOST
        elif tld == "nl":
            return NICClient.NL_HOST
        elif tld == "online":
            return NICClient.ONLINE_HOST
        elif tld == "ooo":
            return NICClient.OOO_HOST
        elif tld == "page":
            return NICClient.PAGE_HOST
        elif tld == "pe":
            return NICClient.PE_HOST
        elif tld == "website":
            return NICClient.WEBSITE_HOST
        elif tld == "za":
            return NICClient.ZA_HOST
        elif tld == "ru":
            return NICClient.RU_HOST
        elif tld == "bz":
            return NICClient.RU_HOST
        elif tld == "city":
            return NICClient.RU_HOST
        elif tld == "design":
            return NICClient.DESIGN_HOST
        elif tld == "studio":
            return NICClient.STUDIO_HOST
        elif tld == "style":
            return NICClient.RU_HOST
        elif tld == "su":
            return NICClient.RU_HOST
        elif tld == "рус" or tld == "xn--p1acf":
            return NICClient.RU_HOST
        elif tld == "direct":
            return NICClient.IDS_HOST
        elif tld == "group":
            return NICClient.IDS_HOST
        elif tld == "immo":
            return NICClient.IDS_HOST
        elif tld == "life":
            return NICClient.IDS_HOST
        elif tld == "fashion":
            return NICClient.GDD_HOST
        elif tld == "vip":
            return NICClient.GDD_HOST
        elif tld == "shop":
            return NICClient.SHOP_HOST
        elif tld == "store":
            return NICClient.STORE_HOST
        elif tld == "дети" or tld == "xn--d1acj3b":
            return NICClient.DETI_HOST
        elif tld == "москва" or tld == "xn--80adxhks":
            return NICClient.MOSKVA_HOST
        elif tld == "рф" or tld == "xn--p1ai":
            return NICClient.RF_HOST
        elif tld == "орг" or tld == "xn--c1avg":
            return NICClient.PIR_HOST
        elif tld == "ng":
            return NICClient.NG_HOST
        elif tld == "укр" or tld == "xn--j1amh":
            return NICClient.UKR_HOST
        elif tld == "tn":
            return NICClient.TN_HOST
        elif tld == "sbs":
            return NICClient.SBS_HOST
        elif tld == "sg":
            return NICClient.SG_HOST
        elif tld == "site":
            return NICClient.SITE_HOST
        elif tld == "ga":
            return NICClient.GA_HOST
        elif tld == "xyz":
            return NICClient.XYZ_HOST
        elif tld in (
            'aaa',
            'aarp',
            'abb',
            'abbott',
            'abc',
            'abogado',
            'abudhabi',
            'ac',
            'accenture',
            'accountant',
            'aco',
            'ad',
            'adult',
            'aeg',
            'af',
            'afl',
            'africa',
            'ag',
            'agakhan',
            'airbus',
            'airtel',
            'akdn',
            'alibaba',
            'alipay',
            'allfinanz',
            'allstate',
            'ally',
            'alsace',
            'alstom',
            'americanfamily',
            'amfam',
            'amsterdam',
            'anz',
            'aol',
            'aquarelle',
            'arab',
            'art',
            'arte',
            'as',
            'asda',
            'asia',
            'at',
            'audi',
            'audio',
            'auspost',
            'auto',
            'autos',
            'aw',
            'baby',
            'bank',
            'bar',
            'barcelona',
            'barclaycard',
            'barclays',
            'barefoot',
            'baseball',
            'basketball',
            'bauhaus',
            'bayern',
            'bbc',
            'bbt',
            'bcg',
            'bcn',
            'beats',
            'beauty',
            'beer',
            'berlin',
            'best',
            'bestbuy',
            'bh',
            'bharti',
            'bible',
            'bid',
            'biz',
            'bj',
            'blackfriday',
            'blockbuster',
            'blog',
            'bloomberg',
            'bm',
            'bms',
            'bmw',
            'bnpparibas',
            'bo',
            'boats',
            'boehringer',
            'bofa',
            'bond',
            'bosch',
            'bostik',
            'boston',
            'box',
            'bradesco',
            'bridgestone',
            'brother',
            'build',
            'buzz',
            'bzh',
            'cam',
            'canon',
            'capetown',
            'capitalone',
            'car',
            'cars',
            'casa',
            'case',
            'cat',
            'catholic',
            'cba',
            'cd',
            'ceo',
            'cern',
            'cfa',
            'cfd',
            'ch',
            'chanel',
            'charity',
            'chintai',
            'christmas',
            'ci',
            'cipriani',
            'citadel',
            'clinique',
            'cloud',
            'club',
            'clubmed',
            'college',
            'commbank',
            'compare',
            'comsec',
            'cooking',
            'coop',
            'corsica',
            'coupon',
            'courses',
            'cpa',
            'creditunion',
            'cricket',
            'crown',
            'crs',
            'cruise',
            'cuisinella',
            'cv',
            'cx',
            'cyou',
            'cz',
            'data',
            'date',
            'dds',
            'dealer',
            'deloitte',
            'delta',
            'diet',
            'discover',
            'dish',
            'dnp',
            'dot',
            'download',
            'dtv',
            'dubai',
            'durban',
            'dvag',
            'dvr',
            'dz',
            'earth',
            'ec',
            'eco',
            'edeka',
            'emerck',
            'epson',
            'ericsson',
            'erni',
            'es',
            'eurovision',
            'eus',
            'extraspace',
            'fage',
            'faith',
            'fans',
            'fedex',
            'ferrari',
            'fidelity',
            'fido',
            'film',
            'firestone',
            'firmdale',
            'fishing',
            'fit',
            'flowers',
            'fm',
            'fo',
            'foundation',
            'fox',
            'fr',
            'fresenius',
            'frl',
            'frogans',
            'fun',
            'gal',
            'gallo',
            'gallup',
            'game',
            'garden',
            'gay',
            'gd',
            'gdn',
            'ge',
            'gea',
            'gent',
            'genting',
            'george',
            'ggee',
            'gh',
            'gives',
            'giving',
            'gl',
            'gmo',
            'gmx',
            'godaddy',
            'goldpoint',
            'goodyear',
            'gop',
            'gov',
            'gp',
            'grocery',
            'gs',
            'guitars',
            'hair',
            'hamburg',
            'hdfc',
            'hdfcbank',
            'help',
            'helsinki',
            'hermes',
            'hiphop',
            'hkt',
            'homedepot',
            'homes',
            'honda',
            'horse',
            'host',
            'hosting',
            'hotels',
            'ht',
            'hu',
            'hughes',
            'hyundai',
            'ibm',
            'icbc',
            'ice',
            'icu',
            'ifm',
            'ikano',
            'im',
            'imamat',
            'inc',
            'ink',
            'insurance',
            'io',
            'ir',
            'ismaili',
            'istanbul',
            'it',
            'itv',
            'jaguar',
            'java',
            'jeep',
            'jio',
            'jll',
            'joburg',
            'jprs',
            'juniper',
            'kddi',
            'kerryhotels',
            'kerryproperties',
            'kfh',
            'ki',
            'kia',
            'kids',
            'kiwi',
            'kn',
            'komatsu',
            'kosher',
            'krd',
            'kuokgroup',
            'kw',
            'kyoto',
            'la',
            'lacaixa',
            'lamborghini',
            'lamer',
            'landrover',
            'lasalle',
            'latino',
            'latrobe',
            'law',
            'lds',
            'leclerc',
            'lefrak',
            'lego',
            'lexus',
            'lidl',
            'lifeinsurance',
            'llp',
            'loan',
            'locker',
            'lol',
            'london',
            'lotte',
            'love',
            'lpl',
            'lplfinancial',
            'ls',
            'ltda',
            'lundbeck',
            'luxe',
            'luxury',
            'lv',
            'ly',
            'madrid',
            'maif',
            'makeup',
            'man',
            'mango',
            'marriott',
            'mc',
            'mckinsey',
            'md',
            'me',
            'melbourne',
            'men',
            'menu',
            'merck',
            'merckmsd',
            'mg',
            'miami',
            'mini',
            'mit',
            'ml',
            'mls',
            'mma',
            'mn',
            'mobile',
            'moe',
            'mom',
            'monash',
            'monster',
            'mormon',
            'moscow',
            'moto',
            'motorcycles',
            'mr',
            'ms',
            'msd',
            'mtr',
            'museum',
            'mw',
            'mz',
            'nab',
            'nagoya',
            'name',
            'nec',
            'netbank',
            'next',
            'nextdirect',
            'nf',
            'ngo',
            'nhk',
            'nico',
            'nikon',
            'nissay',
            'nokia',
            'norton',
            'nowtv',
            'nra',
            'nrw',
            'ntt',
            'nyc',
            'obi',
            'observer',
            'okinawa',
            'olayan',
            'olayangroup',
            'ollo',
            'one',
            'ong',
            'open',
            'oracle',
            'orange',
            'origins',
            'osaka',
            'otsuka',
            'ott',
            'ovh',
            'paris',
            'party',
            'pccw',
            'pg',
            'philips',
            'phone',
            'photo',
            'physio',
            'pics',
            'pictet',
            'ping',
            'playstation',
            'pm',
            'pnc',
            'pohl',
            'politie',
            'porn',
            'post',
            'press',
            'progressive',
            'protection',
            'pw',
            'pwc',
            'qpon',
            'quebec',
            'quest',
            'racing',
            'radio',
            're',
            'realty',
            'redumbrella',
            'reit',
            'reliance',
            'ren',
            'rent',
            'rest',
            'review',
            'rexroth',
            'rich',
            'richardli',
            'ricoh',
            'ril',
            'rodeo',
            'rogers',
            'rugby',
            'ruhr',
            'rwe',
            'ryukyu',
            'saarland',
            'safety',
            'sakura',
            'samsclub',
            'samsung',
            'sandvik',
            'sandvikcoromant',
            'sanofi',
            'sap',
            'saxo',
            'sb',
            'sbi',
            'sc',
            'scb',
            'schmidt',
            'scholarships',
            'schwarz',
            'science',
            'scot',
            'sd',
            'seat',
            'security',
            'seek',
            'select',
            'seven',
            'sew',
            'sex',
            'sfr',
            'sh',
            'shangrila',
            'sina',
            'skin',
            'sl',
            'sling',
            'sm',
            'smart',
            'sn',
            'sncf',
            'so',
            'softbank',
            'song',
            'sony',
            'spa',
            'space',
            'sport',
            'srl',
            'ss',
            'st',
            'stada',
            'star',
            'statebank',
            'stc',
            'stcgroup',
            'stockholm',
            'storage',
            'stream',
            'study',
            'sucks',
            'surf',
            'suzuki',
            'swiss',
            'sydney',
            'tab',
            'taipei',
            'taobao',
            'tatamotors',
            'tatar',
            'tattoo',
            'tc',
            'td',
            'tdk',
            'tech',
            'tel',
            'temasek',
            'teva',
            'tf',
            'tg',
            'thd',
            'theatre',
            'tiaa',
            'tickets',
            'tirol',
            'tl',
            'tm',
            'tmall',
            'tokyo',
            'top',
            'toray',
            'toshiba',
            'total',
            'toyota',
            'trade',
            'travelers',
            'travelersinsurance',
            'trv',
            'tube',
            'tui',
            'tv',
            'tvs',
            'ubank',
            'ubs',
            'uk',
            'unicom',
            'uno',
            'ups',
            'us',
            'vanguard',
            've',
            'vegas',
            'verisign',
            'versicherung',
            'vg',
            'vig',
            'viking',
            'visa',
            'viva',
            'vodka',
            'volvo',
            'voting',
            'walmart',
            'walter',
            'webcam',
            'weber',
            'wedding',
            'weibo',
            'weir',
            'wf',
            'whoswho',
            'wien',
            'wiki',
            'win',
            'wme',
            'woodside',
            'work',
            'wtc',
            'xerox',
            'xin',
            'xn--11b4c3d',
            'xn--1ck2e1b',
            'xn--3pxu8k',
            'xn--42c2d9a',
            'xn--4gbrim',
            'xn--5su34j936bgsg',
            'xn--5tzm5g',
            'xn--80aqecdr1a',
            'xn--80asehdb',
            'xn--80aswg',
            'xn--8y0a063a',
            'xn--9dbq2a',
            'xn--9krt00a',
            'xn--b4w605ferd',
            'xn--bck1b9a5dre4c',
            'xn--c2br7g',
            'xn--cck2b3b',
            'xn--eckvdtc9d',
            'xn--fct429k',
            'xn--fhbei',
            'xn--fzys8d69uvgm',
            'xn--g2xx48c',
            'xn--gckr3f0f',
            'xn--gk3at1e',
            'xn--i1b6b1a6a2e',
            'xn--j1aef',
            'xn--jvr189m',
            'xn--kcrx77d1x4a',
            'xn--kput3i',
            'xn--mgba7c0bbn0a',
            'xn--mgbab2bd',
            'xn--mgbca7dzdo',
            'xn--mgbi4ecexp',
            'xn--mk1bu44c',
            'xn--mxtq1m',
            'xn--ngbc5azd',
            'xn--ngbe9e0a',
            'xn--ngbrx',
            'xn--nqv7f',
            'xn--nqv7fs00ema',
            'xn--pssy2u',
            'xn--rovu88b',
            'xn--ses554g',
            'xn--t60b56a',
            'xn--tckwe',
            'xn--tiq49xqyj',
            'xn--vermgensberater-ctb',
            'xn--vermgensberatung-pwb',
            'xn--w4r85el8fhu5dnra',
            'xn--w4rs40l',
            'xxx',
            'yachts',
            'yahoo',
            'yandex',
            'yoga',
            'yokohama',
            'yt',
            'zara',
            'zero',
            'zuerich',
        ):
            return "whois.nic." + tld
        elif tld in (
            'in',
            'xn--2scrj9c',
            'xn--3hcrj9c',
            'xn--45br5cyl',
            'xn--45brj9c',
            'xn--fpcrj9c3d',
            'xn--gecrj9c',
            'xn--h2breg3eve',
            'xn--h2brj9c',
            'xn--h2brj9c8c',
            'xn--mgbbh1a',
            'xn--mgbbh1a71e',
            'xn--mgbgu82a',
            'xn--rvc1e0am3e',
            'xn--s9brj9c',
            'xn--xkc2dl3a5ee0h',
        ):
            return 'whois.nixiregistry.in'
        elif tld in (
            'click',
            'country',
            'diy',
            'feedback',
            'food',
            'forum',
            'hiv',
            'lifestyle',
            'living',
            'pid',
            'property',
            'sexy',
            'trust',
            'vana',
        ):
            return 'whois.registry.click'
        elif tld in (
            'datsun',
            'fujitsu',
            'hisamitsu',
            'hitachi',
            'infiniti',
            'jcb',
            'mitsubishi',
            'nissan',
            'panasonic',
            'sharp',
            'yodobashi',
        ):
            return 'whois.nic.gmo'
        elif tld in (
            'wang',
            'xn--30rr7y',
            'xn--3bst00m',
            'xn--45q11c',
            'xn--6qq986b3xl',
            'xn--9et52u',
            'xn--czru2d',
            'xn--efvy88h',
            'xn--fiq64b',
            'xn--hxt814e',
        ):
            return 'whois.gtld.zdns.cn'
        elif tld in (
            'anquan',
            'shouji',
            'xihuan',
            'xn--3ds443g',
            'xn--fiq228c5hs',
            'xn--vuq861b',
            'yun',
        ):
            return 'whois.teleinfo.cn'
        elif tld in (
            'xn--1qqw23a',
            'xn--55qx5d',
            'xn--io0a7i',
            'xn--xhq521b',
        ):
            return 'whois.ngtld.cn'
        elif tld in (
            'lc',
            'pr',
            'schaeffler',
        ):
            return 'whois.afilias-srs.net'
        elif tld in (
            'cn',
            'xn--fiqs8s',
            'xn--fiqz9s',
        ):
            return 'whois.cnnic.cn'
        elif tld in (
            'eu',
            'xn--e1a4c',
            'xn--qxa6a',
        ):
            return 'whois.eu'
        elif tld in (
            'kr',
            'xn--3e0b707e',
            'xn--cg4bki',
        ):
            return 'whois.kr'
        elif tld in (
            'tw',
            'xn--kprw13d',
            'xn--kpry57d',
        ):
            return 'whois.twnic.net.tw'
        elif tld in (
            'ae',
            'xn--mgbaam7a8h',
        ):
            return 'whois.aeda.net.ae'
        elif tld in (
            'am',
            'xn--y9a3aq',
        ):
            return 'whois.amnic.net'
        elif tld in (
            'xn--55qw42g',
            'xn--zfr164b',
        ):
            return 'whois.conac.cn'
        elif tld in (
            'arpa',
            'int',
        ):
            return NICClient.IANAHOST
        elif tld in (
            'gi',
            'vc',
        ):
            return NICClient.IDS_HOST
        elif tld in (
            'il',
            'xn--4dbrk0ce',
        ):
            return 'whois.isoc.org.il'
        elif tld in (
            'mk',
            'xn--d1alf',
        ):
            return 'whois.marnet.mk'
        elif tld in (
            'gf',
            'mq',
        ):
            return 'whois.mediaserv.net'
        elif tld in (
            'mo',
            'xn--mix891f',
        ):
            return 'whois.monic.mo'
        elif tld in (
            'my',
            'xn--mgbx4cd0ab',
        ):
            return 'whois.mynic.my'
        elif tld in (
            'sa',
            'xn--mgberp4a5d4ar',
        ):
            return 'whois.nic.net.sa'
        elif tld in (
            'iq',
            'xn--mgbtx2b',
        ):
            return 'whois.reg.iq'
        elif tld in (
            'om',
            'xn--mgb9awbf',
        ):
            return 'whois.registry.om'
        elif tld in (
            'qa',
            'xn--wgbl6a',
        ):
            return 'whois.registry.qa'
        elif tld in (
            'rs',
            'xn--90a3ac',
        ):
            return 'whois.rnids.rs'
        elif tld in (
            'cologne',
            'koeln',
        ):
            return 'whois.ryce-rsp.com'
        elif tld in (
            'th',
            'xn--o3cw4h',
        ):
            return 'whois.thnic.co.th'
        elif tld in (
            'sy',
            'xn--ogbpf8fl',
        ):
            return 'whois.tld.sy'
        elif tld in (
            'com',
            'net',
        ):
            return 'whois.verisign-grs.com'
        elif tld == "cc":
            return 'ccwhois.verisign-grs.com'
        elif tld == "ps":
            return 'registry.ps'
        elif tld == "vi":
            return 'virgil.nic.vi'
        elif tld == "aero":
            return 'whois.aero'
        elif tld == "gn":
            return 'whois.ande.gov.gn'
        elif tld == "xn--pgbs0dh":
            return NICClient.TN_HOST
        elif tld == "au":
            return 'whois.auda.org.au'
        elif tld == "ax":
            return 'whois.ax'
        elif tld == "bn":
            return 'whois.bnnic.bn'
        elif tld == "xn--90ais":
            return 'whois.cctld.by'
        elif tld == "uz":
            return 'whois.cctld.uz'
        elif tld == "ug":
            return 'whois.co.ug'
        elif tld == "dm":
            return 'whois.dmdomains.dm'
        elif tld == "vu":
            return 'whois.dnrs.vu'
        elif tld == "be":
            return 'whois.dns.be'
        elif tld == "lu":
            return 'whois.dns.lu'
        elif tld == "pl":
            return 'whois.dns.pl'
        elif tld == "pt":
            return 'whois.dns.pt'
        elif tld == "gq":
            return 'whois.dominio.gq'
        elif tld == "cf":
            return 'whois.dot.cf'
        elif tld == "tk":
            return 'whois.dot.tk'
        elif tld == "edu":
            return 'whois.educause.edu'
        elif tld == "et":
            return 'whois.ethiotelecom.et'
        elif tld == "fi":
            return 'whois.fi'
        elif tld == "bd":
            return 'whois.get.bd'
        elif tld == "gg":
            return 'whois.gg'
        elif tld == "baidu":
            return 'whois.gtld.knet.cn'
        elif tld == "xn--j6w193g":
            return NICClient.HK_HOST
        elif tld == "nu":
            return 'whois.iis.nu'
        elif tld == "se":
            return 'whois.iis.se'
        elif tld == "xn--90ae":
            return 'whois.imena.bg'
        elif tld == "nz":
            return 'whois.irs.net.nz'
        elif tld == "is":
            return 'whois.isnic.is'
        elif tld == "je":
            return 'whois.je'
        elif tld == "ke":
            return 'whois.kenic.or.ke'
        elif tld == "kg":
            return 'whois.kg'
        elif tld == "ky":
            return 'whois.kyregistry.ky'
        elif tld == "lb":
            return 'whois.lbdr.org.lb'
        elif tld == "xn--l1acc":
            return 'whois.mn'
        elif tld == "nc":
            return 'whois.nc'
        elif tld == "xn--lgbbat1ad8j":
            return 'whois.nic.dz'
        elif tld == "xn--mgba3a4f16a":
            return 'whois.nic.ir'
        elif tld == "xn--80ao21a":
            return NICClient.KZ_HOST
        elif tld == "xn--q7ce6a":
            return 'whois.nic.la'
        elif tld == "xn--mgbah1a3hjkrd":
            return 'whois.nic.mr'
        elif tld == "uy":
            return 'whois.nic.org.uy'
        elif tld == "sener":
            return 'whois.nic.rwe'
        elif tld == "no":
            return NICClient.NORIDHOST
        elif tld == "pk":
            return 'whois.pknic.net.pk'
        elif tld == "xn--ygbi2ammx":
            return 'whois.pnina.ps'
        elif tld == "org":
            return NICClient.PIR_HOST
        elif tld == "bg":
            return 'whois.register.bg'
        elif tld == "si":
            return 'whois.register.si'
        elif tld == "bf":
            return 'whois.registre.bf'
        elif tld == "ma":
            return 'whois.registre.ma'
        elif tld == "br":
            return NICClient.BNICHOST
        elif tld == "co":
            return 'whois.registry.co'
        elif tld == "gift":
            return 'whois.registry.gift'
        elif tld == "mm":
            return 'whois.registry.gov.mm'
        elif tld == "gy":
            return 'whois.registry.gy'
        elif tld == "hm":
            return 'whois.registry.hm'
        elif tld == "pf":
            return 'whois.registry.pf'
        elif tld == "music":
            return 'whois.registryservices.music'
        elif tld == "rw":
            return 'whois.ricta.org.rw'
        elif tld == "ro":
            return 'whois.rotld.ro'
        elif tld == "sk":
            return 'whois.sk-nic.sk'
        elif tld == "sr":
            return 'whois.sr'
        elif tld == "sx":
            return 'whois.sx'
        elif tld == "xn--clchc0ea0b2g2a9gcd":
            return 'whois.ta.sgnic.sg'
        elif tld == "ee":
            return 'whois.tld.ee'
        elif tld == "mu":
            return 'whois.tld.mu'
        elif tld == "to":
            return 'whois.tonicregistry.to'
        elif tld == "tr":
            return 'whois.trabis.gov.tr'
        elif tld == "tz":
            return 'whois.tznic.or.tz'
        elif tld == "ua":
            return 'whois.ua'
        elif tld == "link":
            return 'whois.uniregistry.net'
        elif tld == "ie":
            return 'whois.weare.ie'
        elif tld == "ws":
            return 'whois.website.ws'
        elif tld == "ye":
            return 'whois.y.net.ye'
        elif tld == "xn--yfro4i67o":
            return 'whois.zh.sgnic.sg'
        elif tld == "zm":
            return 'whois.zicta.zm'
        elif tld == "bi":
            return 'whois1.nic.bi'
        elif tld == "fj":
            return 'www.whois.fj'
        else:
            return self.findwhois_iana(tld, timeout=timeout)
            # server = tld + NICClient.QNICHOST_TAIL
            # try:
            #    socket.gethostbyname(server)
            # except socket.gaierror:
            #    server = NICClient.QNICHOST_HEAD + tld
            # return server

    def whois_lookup(
        self, options: Optional[dict], query_arg: str, flags: int, quiet: bool = False, ignore_socket_errors: bool = True, timeout: int = 10
    ) -> str:
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records.  If `quiet` is `True`, no message
        will be printed to STDOUT when a socket error is encountered.
        If `ignore_socket_errors` is `False`, will raise an exception
        instead of returning a string containing the error."""
        nichost = None
        # whoud happen when this function is called by other than main
        if options is None:
            options = {}

        if ("whoishost" not in options or options["whoishost"] is None) and (
            "country" not in options or options["country"] is None
        ):
            self.use_qnichost = True
            options["whoishost"] = NICClient.NICHOST
            if not (flags & NICClient.WHOIS_QUICK):
                flags |= NICClient.WHOIS_RECURSE

        if "country" in options and options["country"] is not None:
            result = self.whois(
                query_arg,
                options["country"] + NICClient.QNICHOST_TAIL,
                flags,
                quiet=quiet,
                ignore_socket_errors=ignore_socket_errors,
                timeout=timeout
            )
        elif self.use_qnichost:
            nichost = self.choose_server(query_arg, timeout=timeout)
            if nichost is not None:
                result = self.whois(query_arg, nichost, flags, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
            else:
                result = ""
        else:
            result = self.whois(query_arg, options["whoishost"], flags, quiet=quiet, ignore_socket_errors=ignore_socket_errors, timeout=timeout)
        return result


def parse_command_line(argv: list[str]) -> tuple[optparse.Values, list[str]]:
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option(
        "-a",
        "--arin",
        action="store_const",
        const=NICClient.ANICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.ANICHOST,
    )
    parser.add_option(
        "-A",
        "--apnic",
        action="store_const",
        const=NICClient.PNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.PNICHOST,
    )
    parser.add_option(
        "-b",
        "--abuse",
        action="store_const",
        const=NICClient.ABUSEHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.ABUSEHOST,
    )
    parser.add_option(
        "-c",
        "--country",
        action="store",
        type="string",
        dest="country",
        help="Lookup using country-specific NIC",
    )
    parser.add_option(
        "-d",
        "--mil",
        action="store_const",
        const=NICClient.DNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.DNICHOST,
    )
    parser.add_option(
        "-g",
        "--gov",
        action="store_const",
        const=NICClient.GNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.GNICHOST,
    )
    parser.add_option(
        "-h",
        "--host",
        action="store",
        type="string",
        dest="whoishost",
        help="Lookup using specified whois host",
    )
    parser.add_option(
        "-i",
        "--nws",
        action="store_const",
        const=NICClient.INICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.INICHOST,
    )
    parser.add_option(
        "-I",
        "--iana",
        action="store_const",
        const=NICClient.IANAHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.IANAHOST,
    )
    parser.add_option(
        "-l",
        "--lcanic",
        action="store_const",
        const=NICClient.LNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.LNICHOST,
    )
    parser.add_option(
        "-m",
        "--ra",
        action="store_const",
        const=NICClient.MNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.MNICHOST,
    )
    parser.add_option(
        "-p",
        "--port",
        action="store",
        type="int",
        dest="port",
        help="Lookup using specified tcp port",
    )
    parser.add_option(
        "--prefer-ipv6",
        action="store_true",
        dest="prefer_ipv6",
        default=False,
        help="Prioritize IPv6 resolution for WHOIS servers",
    )
    parser.add_option(
        "-Q",
        "--quick",
        action="store_true",
        dest="b_quicklookup",
        help="Perform quick lookup",
    )
    parser.add_option(
        "-r",
        "--ripe",
        action="store_const",
        const=NICClient.RNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.RNICHOST,
    )
    parser.add_option(
        "-R",
        "--ru",
        action="store_const",
        const="ru",
        dest="country",
        help="Lookup Russian NIC",
    )
    parser.add_option(
        "-6",
        "--6bone",
        action="store_const",
        const=NICClient.SNICHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.SNICHOST,
    )
    parser.add_option(
        "-n",
        "--ina",
        action="store_const",
        const=NICClient.PANDIHOST,
        dest="whoishost",
        help="Lookup using host " + NICClient.PANDIHOST,
    )
    parser.add_option(
        "-t",
        "--timeout",
        action="store",
        type="int",
        dest="timeout",
        help="Set timeout for WHOIS request",
    )
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


if __name__ == "__main__":
    flags = 0
    options, args = parse_command_line(sys.argv)
    nic_client = NICClient(prefer_ipv6=options.prefer_ipv6)
    if options.b_quicklookup:
        flags = flags | NICClient.WHOIS_QUICK
    logger.debug(nic_client.whois_lookup(options.__dict__, args[1], flags))
