from wsgiref.simple_server import make_server
from .api import mkapp
app = mkapp()


def app_factory(global_config, **local_config):
    return mkapp(global_config, **local_config)


def server_runner(*args):
    _app = args[0]
    local_config = args[1]
    port = int(local_config.get('bind_address', 8080))
    host = local_config.get('port', '0.0.0.0')
    s = make_server(host, port, _app)
    s.serve_forever()


def main():
    server_runner(mkapp(), bind_address='0.0.0.0', port=8080)


if __name__ == '__main__':
    main()