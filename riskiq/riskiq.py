import re
import secrets
from telnetlib import IP
import redis
import pickle
import requests
import ipaddress
from lighthouse import *
from lighthouse_ontology import *
from netaddr import IPNetwork
from passivetotal import analyzer

from datetime import datetime, timezone, timedelta


DISPLAY_CATEGORY = "PassiveTotal"

ENRICH_DOMAIN_UUID4 = "ebfdb41d-5d07-4dc4-a127-469bd7de1b4e"
ENRICH_DOMAIN_NAME  = "PassiveTotal"

PDNS_RESOLVE_TYPE_EMAIL  = "email"
PDNS_RESOLVE_TYPE_DOMAIN = "domain"
PDNS_RESOLVE_TYPE_IP     = "ip"

DOMAINS_FILTERS = [".+\.google\.com$", ".+\.googlemail\.com", ".+\.domaincontrol\.com", ".+\.registrar-servers\.com", ".+\.clients\.your-server\.de", ".+\.regway\.com"]
EMAILS_FILTERS  = [".+\.whoisprivacyservice\.org$", ".+\@amazon\.com$", ".+\@domainsbyproxy\.com", ".+\@registrar-servers\.com", ".+\@namecheap\.com", ".+\@whoisguard\.com", "\@withheldforprivacy\.com"]
WHOIS_FILTERS = ["Redacted for Privacy"]

ASN_PARSER = "(AS[0-9]+)"
ASN_UNK = "AS0000U"

#######################################################################################
# Cache                                                                               #
#######################################################################################

CACHE = {}

def cache_line(_Type, _Key, _Line):
    global CACHE
    fqkey = f"{_Type.__name__}.{_Key}"
    value = pickle.dumps(_Line)

    CACHE[fqkey] = value


def load_line(_Type, _Key):
    global CACHE
    fqkey = f"{_Type.__name__}.{_Key}"
    if fqkey not in CACHE:
        return None

    value = CACHE[fqkey]

    return pickle.loads(value)
    
########################################################################################
# Tables                                                                               #
########################################################################################


class DomainResolve(metaclass=Header):
    display_name = 'Domain and Ip'

    Domain    = Field('domain', ValueType.String)
    Ip        = Field('ip', ValueType.String)
    
    MalwareHashes = Field('malware_hashes', ValueType.Integer)
    Certificates  = Field('certificates', ValueType.Integer)
    Resolves      = Field('resolves', ValueType.Integer)

    Asn           = Field('asn', ValueType.String)
    Netblock      = Field('netblock', ValueType.String)

    FirstSeen     = Field('first_seen', ValueType.Datetime)
    LastSeen      = Field('last_seen', ValueType.Datetime)


class RelatedDomains(metaclass=Header):
    display_name = 'Related domains'

    Domain    = Field('domain', ValueType.String)
    Related   = Field('related', ValueType.String)
    Why       = Field('why', ValueType.String)
    FirstSeen = Field('first_seen', ValueType.Datetime)
    LastSeen  = Field('last_seen', ValueType.Datetime)

class SubDomains(metaclass=Header):
    display_name = 'Sub domains'

    Domain    = Field('domain', ValueType.String)
    Subdomain = Field('subdomain', ValueType.String)

class RelatedEmails(metaclass=Header):
    display_name = 'Related E-Mails'

    Domain    = Field('domain', ValueType.String)
    Email     = Field('email', ValueType.String)
    Why       = Field('why', ValueType.String)
    FirstSeen = Field('first_seen', ValueType.Datetime)
    LastSeen  = Field('last_seen', ValueType.Datetime)

class RegistrantInfo(metaclass=Header):
    display_name = 'Registrants Info'

    Domain          = Field('domain', ValueType.String)
    Email           = Field('email', ValueType.String)
    Phone           = Field('phone', ValueType.String)
    Name            = Field('name', ValueType.String)
    Org             = Field('org', ValueType.String)
    DateRegistered  = Field('date_registered', ValueType.Datetime)
    DateLoaded      = Field('date_loaded', ValueType.Datetime)
    LastSeen        = Field('last_seen', ValueType.Datetime)


class IpCertificateInfo(metaclass=Header):
    Ip = Field('ip', ValueType.String)
    Fingerprint = Field('fingerprint', ValueType.String)
    SerialNumber = Field('serial_number', ValueType.String)
    Sha1 = Field('sha1', ValueType.String)
    Hash = Field('hash', ValueType.String)

    FirstSeen = Field('first_seen', ValueType.Datetime)
    LastSeen  = Field('last_seen', ValueType.Datetime)

    DateIssued = Field('date_issued', ValueType.Datetime)
    DateExpires = Field('date_expires', ValueType.Datetime)

    IssuerCommonName = Field('issuer_common_name', ValueType.String)
    IssuerCountry = Field('issuer_country', ValueType.String)
    IssuerEmailAddress = Field('issuer_email_address', ValueType.String)
    IssuerGivenName = Field('issuer_given_name', ValueType.String)
    IssuerLocalityName = Field('issuer_locality_name', ValueType.String)
    IssuerOrganizationName = Field('issuer_organization_name', ValueType.String)
    IssuerOrganizationUnitName = Field('issuer_organization_unit_name', ValueType.String)
    IssuerProvince = Field('issuer_province', ValueType.String)
    IssuerStateOrProvinceName = Field('issuer_state_or_province_name', ValueType.String)
    IssuerStreetAddress = Field('issuer_street_address', ValueType.String)
    IssuerSurname = Field('issuer_surname', ValueType.String)

    SubjectAlternativeNames = Field('subject_alternative_names', ValueType.String)
    SubjectCommonName = Field('subject_common_name', ValueType.String)
    SubjectCountry = Field('subject_country', ValueType.String)
    SubjectEmailAddress = Field('subject_email_address', ValueType.String)
    SubjectGivenName = Field('subject_given_name', ValueType.String)
    SubjectLocalityName = Field('subject_locality_name', ValueType.String)
    SubjectOrganizationName  = Field('subject_organization_name', ValueType.String)
    SubjectOrganizationUnitName = Field('subject_organization_unit_name', ValueType.String)
    SubjectProvince = Field('subject_province', ValueType.String)
    SubjectStateOrProvinceName = Field('subject_state_or_province_name', ValueType.String)
    SubjectStreetAddress = Field('subject_street_address', ValueType.String)
    SubjectSurname = Field('subject_surname', ValueType.String)


class ComponentInfo(metaclass=Header):
    Ip = Field('ip', ValueType.String)
    Label = Field('label', ValueType.String)
    Category = Field('category', ValueType.String)
    FirstSeen = Field('first_seen', ValueType.Datetime)
    LastSeen  = Field('last_seen', ValueType.Datetime)

class CookieInfo(metaclass=Header):
    Ip = Field('ip', ValueType.String)
    Name = Field('name', ValueType.String)
    Value = Field('value', ValueType.String)
    FirstSeen = Field('first_seen', ValueType.Datetime)
    LastSeen  = Field('last_seen', ValueType.Datetime)

########################################################################################
# Schema                                                                               #
########################################################################################

class NetworkSegment(metaclass=Object):
    cidr = Attribute("cidr", ValueType.String)

    IdentAttrs = CaptionAttrs = [cidr]

class ExtendedDomainToIp(metaclass=Link):
    name = "ExtendedDomainToIpLink"

    FirstSeen = Attribute("FirstSeen", ValueType.Datetime)
    LastSeen  = Attribute("LastSeen", ValueType.Datetime)

    CaptionAttrs = [FirstSeen, LastSeen]

    Begin = Domain
    End = IPAddress


class IpToNetworkSegment(metaclass=Link):
    name = "Link_IpToNetworkSegment"

    Value = Attributes.System.IPAddress
    CaptionAttrs = [Value]

    Begin = IPAddress
    End   = NetworkSegment


class NetworkSegmentToAutonomusSystem(metaclass=Link):
    name = "Link_NetworkSegmentToAutonomusSystem"

    Value = Attribute("NetworkSegment", ValueType.String)
    CaptionAttrs = [Value]

    Begin = NetworkSegment
    End   = AutonomousSystem

class SchemaResolvedDomain(metaclass=Schema):
    name = f'Schema - PassiveTotal ResolvedDomain'
    Header = DomainResolve

    SchemaIp       = SchemaObject(IPAddress, mapping={IPAddress.IPAddress: Header.Ip})
    SchemaDomain   = SchemaObject(Domain, mapping={Domain.Domain: Header.Domain})
    SchemaAsn      = SchemaObject(AutonomousSystem, mapping={AutonomousSystem.ASN: Header.Asn})
    SchemaNetblock = SchemaObject(NetworkSegment, mapping={NetworkSegment.cidr: Header.Netblock})

    SchemaLinkIpToDomain = ExtendedDomainToIp.between(SchemaDomain, SchemaIp, 
        mapping={
            ExtendedDomainToIp.FirstSeen: Header.FirstSeen, 
            ExtendedDomainToIp.LastSeen:  Header.LastSeen
        }
    )

    SchemaIpToNetworkSegment              = IpToNetworkSegment.between(SchemaIp, SchemaNetblock, {IpToNetworkSegment.Value: Header.Ip})
    SchemaNetworkSegmentToAutonomusSystem = NetworkSegmentToAutonomusSystem.between(SchemaNetblock, SchemaAsn, {NetworkSegmentToAutonomusSystem.Value: Header.Netblock})

########################################################################################
# Utils                                                                                #
########################################################################################

class InvalidAsn(Exception):
    def __init__(self, asn) -> None:
        self.asn = asn
        super().__init__(f"Bas asn: {asn}")


_domains_filters = [re.compile(v) for v in DOMAINS_FILTERS]
_emails_filters  = [re.compile(v) for v in EMAILS_FILTERS]
_whois_filters   = [re.compile(v, re.IGNORECASE) for v in WHOIS_FILTERS]
_asn_parser = re.compile(ASN_PARSER)

def regex_filter(re, val, match=True) -> bool:
    for r in re:
        if match:
            res = r.match(val)
        else:
            res = r.findall(val)

        if res:
            return False
    
    return True


def is_valid_domain(domain):
    return regex_filter(_domains_filters, domain)


def is_valid_email(email):
    return regex_filter(_emails_filters, email)


def normalize_asn(asn):
    if not asn:
        return ASN_UNK

    matches = _asn_parser.findall(asn)
    return matches[0]


########################################################################################
# RiskIQ Providers                                                                     #
########################################################################################

def provide_domain_resolutions(hostname, sink, logger, params):
    """ Provide information about history of domain resolves """
    for resolution in hostname.resolutions:        
        if resolution.resolvetype == PDNS_RESOLVE_TYPE_IP:
            ip_str = resolution.resolve

            if not ip_str or ipaddress.ip_address(ip_str).version == 6:
                continue
            
            cached = load_line(DomainResolve, hostname.hostname)
            if cached:
                continue

            logger.info(f"gather info for one of resolves ip={ip_str}")

            number_of_resolves = load_line(int, f"{ip_str}.number_of_resolves")

            if number_of_resolves is None:
                ip = analyzer.IPAddress(ip_str)
                number_of_resolves = ip.summary.pdns
                
                cache_line(int, f"{ip_str}.number_of_resolves", ip.summary.resolutions)

                # Ananlyse will be performed only if IP doesnt have a lot of resolves
                if  number_of_resolves > params.max_number_of_domains:
                    logger.info(f"Too musch resolutions for IP '{ip_str}'. Filtered")
                    continue

                cache_line(int, f"{ip_str}.number_of_malware_hashes", ip.summary.malware_hashes)
                cache_line(int, f"{ip_str}.number_of_certificates",   ip.summary.certificates)
                cache_line(str, f"{ip_str}.netblock",                 ip.summary.netblock)
                cache_line(str, f"{ip_str}.asn",                      normalize_asn(ip.summary.asn))

                try:
                    provide_certificates(ip, sink, logger, params)
                except analyzer._common.AnalyzerError:
                    logger.info(f"WARNING! PassiveTotal internal error was occured. Step: provide_certificates(ip={ip_str})")
                
                try:
                    provide_components(ip, sink, logger, params)
                except analyzer._common.AnalyzerErro:
                    logger.info(f"WARNING! PassiveTotal internal error was occured. Step: provide_components(ip={ip_str})")

                try:
                    provide_cookies(ip, sink, logger, params)
                except analyzer._common.AnalyzerErro:
                    logger.info(f"WARNING! PassiveTotal internal error was occured. Step: provide_components(ip={ip_str})")

            # duplicate 'if' for cases when we encounter IP previously but we should check it again.
            # beacause user can change threshold value we should check it again 
            if  number_of_resolves > params.max_number_of_domains:
                logger.info(f"Too musch resolutions for IP '{ip_str}'. Filtered")
                continue

            line = DomainResolve.create_empty()
            line[DomainResolve.Domain] = hostname.hostname
            line[DomainResolve.Ip]     = ip_str
            
            # cached data / or data from local aggregator
            line[DomainResolve.MalwareHashes] = load_line(int, f"{ip_str}.malware_hashes")
            line[DomainResolve.Certificates]  = load_line(int, f"{ip_str}.number_of_certificates")
            line[DomainResolve.Resolves]      = load_line(int, f"{ip_str}.number_of_resolves")
            line[DomainResolve.Netblock]      = load_line(str, f"{ip_str}.netblock")
            line[DomainResolve.Asn]           = load_line(str, f"{ip_str}.asn")
            
            line[DomainResolve.LastSeen]  = resolution.lastseen
            line[DomainResolve.FirstSeen] = resolution.firstseen
                    
            sink.write_line(line, header_class=DomainResolve)
            
            cache_line(DomainResolve, hostname.hostname, line)

        elif resolution.resolvetype == PDNS_RESOLVE_TYPE_EMAIL:
            if params.enable_predefined_email_filters and not is_valid_email(resolution.resolve):
                continue
                
            line = RelatedEmails.create_empty()
            line[RelatedEmails.Domain] = hostname.hostname
            line[RelatedEmails.Email] = resolution.resolve
            line[RelatedEmails.Why] = resolution.recordtype
            line[RelatedEmails.LastSeen] = resolution.lastseen
            line[RelatedEmails.FirstSeen] = resolution.firstseen
                    
            sink.write_line(line, header_class=RelatedEmails)

        elif resolution.resolvetype == PDNS_RESOLVE_TYPE_DOMAIN:
            if params.enable_predefined_domain_filters and not is_valid_domain(resolution.resolve):
                continue

            line = RelatedDomains.create_empty()
            line[RelatedDomains.Domain] = hostname.hostname
            line[RelatedDomains.Related] = resolution.resolve
            line[RelatedDomains.Why] = resolution.recordtype
            line[RelatedDomains.LastSeen] = resolution.lastseen
            line[RelatedDomains.FirstSeen] = resolution.firstseen

            sink.write_line(line, header_class=RelatedDomains)


def provide_ip_resolutions(ip, sink, logger, params):
    """ Provide information about history of IP resolves """
    domains = []

    cached = load_line(DomainResolve, ip.ip) 
    if cached:
        return

    lines = []
    for resolution in ip.resolutions: 
        if resolution.resolvetype == PDNS_RESOLVE_TYPE_DOMAIN:
            line = DomainResolve.create_empty()
            line[DomainResolve.Domain] = resolution.resolve
            line[DomainResolve.Ip] = ip.ip
            line[DomainResolve.MalwareHashes] = ip.summary.malware_hashes
            line[DomainResolve.Certificates] = ip.summary.certificates
            line[DomainResolve.Resolves] = ip.summary.resolutions 
            line[DomainResolve.Netblock] = ip.summary.netblock
            line[DomainResolve.Asn] = normalize_asn(ip.summary.asn)
            line[DomainResolve.LastSeen] = resolution.lastseen
            line[DomainResolve.FirstSeen] = resolution.firstseen
            
            domains.append(resolution.resolve)
            lines.append(line)
            sink.write_line(line, header_class=DomainResolve)
        else:
            logger.info(resolution.recordtype)
            logger.info(resolution.resolvetype)
            logger.info(resolution)

    cache_line(DomainResolve, ip.ip, lines)

    return list(set(domains))


def provide_certificates(ip, sink, logger, params):
    """ Provide information about history of SSL certificates which were discovered """
    for cert in ip.certificates:
        line = IpCertificateInfo.create_empty()
        line[IpCertificateInfo.Ip]           = ip.ip
        line[IpCertificateInfo.Fingerprint]  = cert.fingerprint
        line[IpCertificateInfo.SerialNumber] = cert.serialNumber
        line[IpCertificateInfo.SerialNumber] = cert.serialNumber
        line[IpCertificateInfo.Sha1] = cert.sha1
        line[IpCertificateInfo.Hash] = cert.hash
        
        line[IpCertificateInfo.FirstSeen] = cert.firstseen
        line[IpCertificateInfo.LastSeen]  = cert.lastseen

        line[IpCertificateInfo.DateIssued] = cert.date_issued
        line[IpCertificateInfo.DateExpires] = cert.date_expires

        line[IpCertificateInfo.IssuerCommonName] = cert.subjectCommonName.value
        line[IpCertificateInfo.IssuerCountry] = cert.subjectCommonName.value
        line[IpCertificateInfo.IssuerEmailAddress] = cert.subjectCountry.value
        line[IpCertificateInfo.IssuerGivenName] = cert.subjectGivenName.value
        line[IpCertificateInfo.IssuerLocalityName] = cert.issuerLocalityName.value
        line[IpCertificateInfo.IssuerOrganizationName] = cert.issuerOrganizationName.value
        line[IpCertificateInfo.IssuerOrganizationUnitName] = cert.issuerOrganizationUnitName.value
        line[IpCertificateInfo.IssuerProvince] = cert.issuerProvince.value
        line[IpCertificateInfo.IssuerStateOrProvinceName] = cert.issuerStateOrProvinceName.value
        line[IpCertificateInfo.IssuerStreetAddress] = cert.issuerStreetAddress.value
        line[IpCertificateInfo.IssuerSurname] = cert.issuerSurname.value

        line[IpCertificateInfo.SubjectAlternativeNames] = cert.subjectAlternativeNames.value
        line[IpCertificateInfo.SubjectCommonName] = cert.subjectCommonName.value
        line[IpCertificateInfo.SubjectCountry] = cert.subjectCountry.value
        line[IpCertificateInfo.SubjectEmailAddress] = cert.subjectEmailAddress.value
        line[IpCertificateInfo.SubjectGivenName] = cert.subjectGivenName.value
        line[IpCertificateInfo.SubjectLocalityName] = cert.subjectLocalityName.value
        line[IpCertificateInfo.SubjectOrganizationName] = cert.subjectOrganizationName.value
        line[IpCertificateInfo.SubjectOrganizationUnitName] = cert.subjectOrganizationUnitName.value
        line[IpCertificateInfo.SubjectProvince] = cert.subjectProvince.value
        line[IpCertificateInfo.SubjectStateOrProvinceName] = cert.subjectStateOrProvinceName.value
        line[IpCertificateInfo.SubjectStreetAddress] = cert.subjectStreetAddress.value
        line[IpCertificateInfo.SubjectSurname] = cert.subjectSurname.value

        sink.write_line(line, header_class=IpCertificateInfo)


def provide_components(ip, sink, logger, params):
    """ Provide information about history of recognized services """
    for comp in ip.components:
        line = ComponentInfo.create_empty()
        line[ComponentInfo.Ip] = ip.ip
        line[ComponentInfo.Label] = comp.label
        line[ComponentInfo.Category] = comp.category
        line[ComponentInfo.FirstSeen] = comp.firstseen
        line[ComponentInfo.LastSeen]  = comp.lastseen

        sink.write_line(line, header_class=ComponentInfo)


def provide_cookies(ip, sink, logger, params):
    """ Provide information about history of cookies """
    for cookie in ip.cookies:
        line = CookieInfo.create_empty()
        line[CookieInfo.Ip] = ip.ip
        line[CookieInfo.Name] = cookie.name
        line[CookieInfo.Value] = cookie.value
        line[CookieInfo.FirstSeen] = cookie.firstseen
        line[CookieInfo.LastSeen]  = cookie.lastseen

        sink.write_line(line, header_class=CookieInfo)


def provide_subdomains(hostname, sink, logger, params):
    """ Provide list of subdomains for domain """
    subdomains = []
    for subdomain in hostname.subdomains:
        fqdn = subdomain.fqdn
            
        line = SubDomains.create_empty()
        line[SubDomains.Domain]    = hostname.hostname
        line[SubDomains.Subdomain] = fqdn

        sink.write_line(line, header_class=SubDomains)
        subdomains.append(fqdn)

    return subdomains


def provide_whois_contact_info(hostname, contact, whois_record, sink, logger, params):
    """ Provide information about registrant """
    if params.enable_predefined_email_filters and contact.email.value and not is_valid_email(contact.email.value):
        return

    if params.enable_predefined_whois_filters and contact.name.value and not regex_filter(_whois_filters, contact.name.value):
        return

    line = RegistrantInfo.create_empty()
    line[RegistrantInfo.Domain] = hostname.hostname 
    line[RegistrantInfo.Email]  = contact.email
    line[RegistrantInfo.Phone]  = contact.telephone
    line[RegistrantInfo.Name]   = contact.name
    line[RegistrantInfo.Org]    = contact.organization
    line[RegistrantInfo.DateRegistered] = whois_record.date_registered
    line[RegistrantInfo.DateLoaded]     = whois_record.date_loaded
    line[RegistrantInfo.LastSeen]       = whois_record.last_seen

    sink.write_line(line, header_class=RegistrantInfo)

    return whois_record.contacts.email


def provide_whois(hostname, sink, logger, params):
    """ Provide information about registrant """
    emails = []
    for whois_record in hostname.whois_history:
            
        r = provide_whois_contact_info(hostname, whois_record.contacts, whois_record, sink, logger, params)
        if r:
            emails.append(r)
            
        if whois_record.tech.email != whois_record.contacts.email:
            r = provide_whois_contact_info(hostname, whois_record.tech, whois_record, sink, logger, params)
            if r:
                emails.append(r)

    return list(set(emails))


########################################################################################
# Tasks                                                                                #
########################################################################################


class PassiveTotalTask(Task):
    def __init__(self):

        self.domains_filters = [re.compile(v) for v in DOMAINS_FILTERS]
        self.emails_filters = [re.compile(v) for v in EMAILS_FILTERS]
        self.whois_filters = [re.compile(v, re.IGNORECASE) for v in WHOIS_FILTERS]

        super().__init__()

    def get_id(self) -> str:
        return ENRICH_DOMAIN_UUID4

    def get_category(self) -> str:
        return DISPLAY_CATEGORY
    
    def get_display_name(self) -> str:
        return ENRICH_DOMAIN_NAME

    def get_schemas(self):
        return SchemaCollection(SchemaResolvedDomain)

    def get_graph_macros(self):
        return MacroCollection(
            Macro(name='Resolved domain macro', 
                  mapping_flags=[GraphMappingFlags.Completely], 
                  schemas=[SchemaResolvedDomain])
        )

    def get_headers(self):
        collection = HeaderCollection()
        collection.add_headers(DomainResolve)
        collection.add_headers(RelatedDomains)
        collection.add_headers(RelatedEmails)
        collection.add_headers(SubDomains)
        collection.add_headers(RegistrantInfo)
        collection.add_headers(IpCertificateInfo)
        collection.add_headers(ComponentInfo)
        collection.add_headers(CookieInfo)
        return collection

    def get_enter_params(self) -> EnterParamCollection:
        params = EnterParamCollection()
        
        params.add_enter_param("apikey", "Key", ValueType.String, required=True, category="Access", description="API key for access to PassiveTotal service")
        params.add_enter_param("username", "Username", ValueType.String, required=True, category="Access", description="Username for access to PassiveTotal service")
        params.add_enter_param("domains", "Domains", ValueType.String, required_group=True, is_array=True, category="Targets", description="Target domains to enrich")
        params.add_enter_param("ips", "IPs", ValueType.String, required_group=True, is_array=True, category="Targets", description="Target IPs to enrich")
        params.add_enter_param("netblocks", "Netblocks", ValueType.String, required_group=True, is_array=True, category="Targets", description="Target netblocks to enrich")
        params.add_enter_param("domains_days_back", "Days back for domain", ValueType.Integer, required=True, default_value=365 * 2, category="Settings", description="Max number of days to search domain")
        params.add_enter_param("ip_days_back", "Days back for IP", ValueType.Integer, required=True, default_value=30*6, category="Settings", description="Max number of days to search IP")
        params.add_enter_param("max_number_of_domains", "Max number of domains per IP", ValueType.Integer, required=True, default_value=100, category="Settings", description="Max number of domains which has being resolved per one IP")
        params.add_enter_param("max_number_of_networks_in_asn", "Max number of networks in ASN", ValueType.Integer, required=True, default_value=10, category="Settings", description="Max number of networks in ASN")
        params.add_enter_param("enable_predefined_domain_filters", "Enable predefined domain filters", ValueType.Boolean, required=True, default_value=True, category="Settings", description="Enable predefined domain filters for any discovered domain entity")
        params.add_enter_param("enable_predefined_email_filters", "Enable predefined email filters", ValueType.Boolean, required=True, default_value=True, category="Settings", description="Enable predefined email filters for any discovered email entity")
        params.add_enter_param("enable_predefined_whois_filters", "Enable predefined whois filters", ValueType.Boolean, required=True, default_value=True, category="Settings", description="Enable predefined whois filters for any discovered whois entity")
        params.add_enter_param("explore_subdomains", "Explore subdomains", ValueType.Boolean, required=True, default_value=True, category="Settings", description="Enable suddomain exploring")
        params.add_enter_param("explore_domains_whois", "Explore domains WHOIS", ValueType.Boolean, required=True, default_value=True, category="Settings", description="Enable whois exploring for domains")

        return params

    def _execute_domains(self, domains, enter_params, result_writer, log_writer, temp_directory_path):
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=enter_params.domains_days_back)

        analyzer.config['start_date'] = past.date().isoformat() + ' 00:00:00'
        analyzer.config['end_date'] = now.date().isoformat() + ' 23:59:59'

        domains_todo = domains
        subdomains = []
        visited = []
        while domains_todo:
            
            domain = domains_todo.pop()
            if domain in visited:
                continue
            visited.append(domain)

            hostname = analyzer.Hostname(domain)
            try:
                if hostname.hostname not in subdomains: # disable recursive exploring of subdomains
                    subdomains.extend(
                        provide_subdomains(hostname, result_writer, log_writer, enter_params)
                    )
                    if enter_params.explore_subdomains:
                        domains_todo.extend(subdomains)

                provide_domain_resolutions(hostname, result_writer, log_writer, enter_params)
                
                try:
                    if enter_params.explore_domains_whois:
                        provide_whois(hostname, result_writer, log_writer, enter_params)
                except requests.exceptions.ConnectionError as ex:
                    log_writer.info(f"WARNING! Get whois info for '{domain}' failed. Connection error")

            except analyzer._common.AnalyzerAPIError:
                log_writer.error(f"Domain '{domain}' enriching failed. Too many requests status code was returned. Probably, count of API searches were over")

    def _execute_ips(self, ips, enter_params, result_writer, log_writer, temp_directory_path):
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=enter_params.ip_days_back)

        analyzer.config['start_date'] = past.date().isoformat() + ' 00:00:00'
        analyzer.config['end_date'] = now.date().isoformat() + ' 23:59:59'

        ip_todo = ips
        visited = []
        while ip_todo:
            
            ip_str = ip_todo.pop()
            if ip_str in visited:
                continue
            visited.append(ip_str)

            if not ip_str or ipaddress.ip_address(ip_str).version == 6:
                continue
            
            log_writer.info(f"Fetch info ip={ip_str}")

            try:
                ip = analyzer.IPAddress(ip_str)
                provide_ip_resolutions(ip, result_writer, log_writer, enter_params)

                provide_certificates(ip, result_writer, log_writer, enter_params)
                provide_components(ip, result_writer, log_writer, enter_params)
                provide_cookies(ip, result_writer, log_writer, enter_params)
            except Exception:
                log_writer.info("Fetch info ip={ip_str} failed")
                analyzer.init(username=enter_params.username, api_key=enter_params.apikey)


    def _execute_netblocks(self, netblocks, enter_params, result_writer, log_writer, temp_directory_path):
        for netblock in netblocks:
            log_writer.info(f"walk through {netblock}")
            self._execute_ips([str(ip) for ip in IPNetwork(netblock)], enter_params, result_writer, log_writer, temp_directory_path)

    def execute(self, enter_params, result_writer, log_writer, temp_directory_path):
        analyzer.init(username=enter_params.username, api_key=enter_params.apikey)
        
        if enter_params.domains:
            self._execute_domains(enter_params.domains, enter_params, result_writer, log_writer, temp_directory_path)

        if enter_params.ips:
            self._execute_ips(enter_params.ips, enter_params, result_writer, log_writer, temp_directory_path)

        if enter_params.netblocks:
            self._execute_netblocks(enter_params.netblocks, enter_params, result_writer, log_writer, temp_directory_path)
