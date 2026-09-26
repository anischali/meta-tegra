#
# Helpers for handling PKCS#11 URIs (RFC 7512) used as signing key or
# certificate references in place of local file names.
#
import urllib.parse

URI_SCHEME = 'pkcs11:'

def is_uri(value):
    """Returns True if value is a PKCS#11 URI rather than a file name."""
    return bool(value) and value.startswith(URI_SCHEME)

def parse_uri(uri):
    """Splits a PKCS#11 URI into a dict of percent-decoded attributes.

    Both path attributes (';'-separated, e.g. token, object, type) and
    query attributes ('&'-separated, e.g. module-path, pin-value,
    pin-source) are returned in the same dict. RFC 7512 places pin-value
    in the query component, but some tools accept it as a path attribute,
    so both locations are handled.
    """
    if not is_uri(uri):
        raise ValueError('not a PKCS#11 URI')
    path, _, query = uri[len(URI_SCHEME):].partition('?')
    attrs = {}
    for component, sep in ((path, ';'), (query, '&')):
        for attr in component.split(sep):
            if not attr:
                continue
            name, eq, value = attr.partition('=')
            if not eq:
                raise ValueError('malformed PKCS#11 URI attribute "%s"' % name)
            attrs[name] = urllib.parse.unquote(value)
    return attrs

def _map_pin_value(uri, replacement):
    path, qmark, query = uri.partition('?')
    def _map(component, sep):
        attrs = [replacement if attr.startswith('pin-value=') else attr
                 for attr in component.split(sep)]
        return sep.join(attr for attr in attrs if attr is not None)
    query = _map(query, '&')
    return _map(path, ';') + (qmark if query else '') + query

def redact(uri):
    """Returns the URI with any pin-value attribute masked, for logging."""
    if not is_uri(uri):
        return uri
    return _map_pin_value(uri, 'pin-value=***')

def without_pin(uri):
    """Returns the URI with any pin-value attribute removed.

    Used where the URI is handed to tools that echo their command line,
    when the PIN is delivered to them through another channel.
    """
    if not is_uri(uri):
        return uri
    return _map_pin_value(uri, None)

def check_uri(d, varname):
    """Validates the PKCS#11 URI held in varname, returning its attributes.

    Signing recipes pass these URIs to shell commands wrapped in single
    quotes, so reject the one URI character that would break that. RFC 7512
    allows it to be percent-encoded as %27 instead.
    """
    import bb
    uri = d.getVar(varname)
    if "'" in uri or '\n' in uri:
        bb.fatal("%s: PKCS#11 URI must not contain a quote or newline; "
                 "percent-encode it instead (%s)" % (varname, redact(uri)))
    try:
        return parse_uri(uri)
    except ValueError as e:
        bb.fatal("%s: %s (%s)" % (varname, e, redact(uri)))

def uri_attr(d, varname, attr):
    """Returns one attribute of the PKCS#11 URI in varname, or ''."""
    if not is_uri(d.getVar(varname)):
        return ''
    return check_uri(d, varname).get(attr, '')

def pin_file(d, varname):
    """Returns the PIN file named by the URI's pin-source attribute, or ''.

    Only local files are supported, given either as a "file:" URI or as
    an absolute path, matching what OpenSSL's pkcs11-provider accepts.
    """
    import bb
    source = uri_attr(d, varname, 'pin-source')
    if not source:
        return ''
    if source.startswith('file:'):
        source = urllib.parse.urlparse(source).path
    if not source.startswith('/'):
        bb.fatal("%s: unsupported pin-source, expected file:<absolute path>" % varname)
    return source
