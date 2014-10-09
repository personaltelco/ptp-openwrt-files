# Generate configuration files for a node.


import getopt
import json
import urllib2


USAGE = '%s [-h|--host] <hostname> | [-n|--node] <nodename>'


class Generator(object):
    """Configuration generator."""

    APIURL = 'https://personaltelco.net/api/v0'

    def __init__(self, host=None, node=None):
        """Constructor."""
        self.host = host
        self.node = node
        self.data = None

        if not (self.host or self.node):
            raise ValueError('Node or host name must be specified.')

        if self.host and self.node:
            raise ValueError('Only node or host must be specified.')

    def retrieve(self):
        """Retrieve configuration information."""
        if self.host:
            url = '%s/hosts/%s' % (self.APIURL, self.host)
        else:
            url = '%s/nodes/%s' % (self.APIURL, self.node)

        response = urllib2.urlopen(url)
        self.data = json.load(response)['data']

    def generate(self):
        """Generate configuration."""
        self.retrieve()

        # TODO do stuff with retrieved data.
        import pprint
        pprint.pprint(self.data)


def main(argv):
    """Generate configuration files."""
    host = None
    node = None

    optlist, args = getopt.getopt(argv[1:], 'h:n:', ['host=', 'node='])

    for opt, val in optlist:
        if opt in ['-h', '--host']:
            host = val
        elif opt in ['-n', '--node']:
            node = val

    try:
        generator = Generator(host=host, node=node)
    except ValueError:
        print USAGE % argv[0]
        return -1

    generator.generate()
    return 0
