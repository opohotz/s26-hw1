# Allowed Modules
import logging
import socket
import sys
import gzip
import ssl
# End of Allowed Modules
# Adding any extra module will result into score of 0

def get_header_value(header_bytes: bytes, name: bytes):
    # name should be lowercase bytes like b"location"
    for line in header_bytes.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            if k.strip().lower() == name:
                return v.strip()
    return None

def decode_chunked(body: bytes) -> bytes:
    out = b""
    i = 0
    while True:
        j = body.find(b"\r\n", i)
        if j == -1:
            break

        size_line = body[i:j]
        if b";" in size_line:   # ignore chunk extensions
            size_line = size_line.split(b";", 1)[0]

        size = int(size_line, 16)
        i = j + 2   # move past \r\n

        if size == 0:
            break

        out += body[i:i+size]  # chunk data
        i += size + 2  # skip data + trailing \r\n

    return out


# 'http://www.example.com'
def retrieve_url(url):
    """
    return bytes of the body of the document at url
    """

    MAX_REDIRECTS = 10
    redirects = 0
    current = url.strip()

    while True:

        method = "GET"
        version = "HTTP/1.1"
        cr = "\r"
        lf = "\n" #"linefeed"
        sp = ' '
        host_hdr = "Host: "
        userAgent = "User-Agent: None"
        connection = "Connection: close"
        https = False
        
        if current.startswith("https://"):
            https = True
            working = current[len("https://"):]
        elif current.startswith("http://"):
            https = False
            working = current[len("http://"):]
        else:
            working = current

        #path split
        if "/" in working:
            host_only, rest = working.split("/", 1)
            path = "/" + rest
        else:
            host_only = working
            path = "/"

        port = 443 if https else 80

        # nonstandard port split (ex: portquiz.net:8080)
        host_value = host_only
        if ":" in host_only:
            host_name, port_str = host_only.rsplit(":", 1)
            if port_str.isdigit():
                host_only = host_name
                port = int(port_str)
                host_value = host_only + ":" + port_str

        message = ( 
            method + sp + path + sp + version + cr + lf + 
            host_hdr + host_value + cr + lf + 
            userAgent + cr + lf + 
            connection + cr + lf + 
            cr + lf
        ).encode()
        
        # --- make connection ---
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # avoid hanging forever on servers that don't close promptly
        s.connect((host_only, port))

        if https:
            ctx = ssl.create_default_context() #creates SSL/TLS config HTTPS rules
            s = ctx.wrap_socket(s, server_hostname=host_only) #TLS handshake on socket

        s.sendall(message)

        response = b"" #read server response
        while True:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            response += chunk

        s.close()
        # --- end connection code ---

        parts = response.split(b"\r\n\r\n", 1)
        if len(parts) != 2:
            return None

        header_bytes, body = parts[0], parts[1]

        # parse status code
        status_line = header_bytes.split(b"\r\n", 1)[0]
        status_parts = status_line.split(b" ")
        if len(status_parts) < 2:
            return None
        try:
            status_code = int(status_parts[1])
        except ValueError:
            return None

        #Follow redirects
        if 300 <= status_code <= 399:
            if redirects >= MAX_REDIRECTS:
                return None

            loc = get_header_value(header_bytes, b"location")
            if loc is None:
                return None

            loc_str = loc.decode("iso-8859-1", "replace")

            # absolute redirect
            if loc_str.startswith("http://") or loc_str.startswith("https://"):
                current = loc_str
            else:
                scheme = "https://" if https else "http://"
                if not loc_str.startswith("/"):
                    loc_str = "/" + loc_str
                current = scheme + host_value + loc_str

            redirects += 1
            continue  # go fetch redirected URL

        #return NONE for non-200
        if status_code != 200:
            return None

        if b"transfer-encoding: chunked" in header_bytes.lower():
            body = decode_chunked(body)

        return body


if __name__ == "__main__":
    out = retrieve_url(sys.argv[1])
    if out is not None:
        sys.stdout.buffer.write(out)