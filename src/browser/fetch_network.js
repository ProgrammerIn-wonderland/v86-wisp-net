"use strict";

/**
 * @constructor
 *
 * @param {BusConnector} bus
 * @param {*=} config
 */
function FetchNetworkAdapter(bus, config)
{
    config = config || {};
    this.bus = bus;
    this.id = config.id || 0;
    this.router_mac = new Uint8Array((config.router_mac || "52:54:0:1:2:3").split(":").map(function(x) { return parseInt(x, 16); }));
    this.router_ip = new Uint8Array((config.router_ip || "192.168.86.1").split(".").map(function(x) { return parseInt(x, 10); }));
    this.vm_ip = new Uint8Array((config.vm_ip || "192.168.86.100").split(".").map(function(x) { return parseInt(x, 10); }));
    this.masquerade = config.masquerade === undefined || !!config.masquerade;
    this.vm_mac = new Uint8Array(6);

    this.tcp_conn = {};

    // Ex: 'https://corsproxy.io/?'
    this.cors_proxy = config.cors_proxy;

    this.bus.register("net" + this.id + "-mac", function(mac) {
        this.vm_mac = new Uint8Array(mac.split(":").map(function(x) { return parseInt(x, 16); }));
    }, this);
    this.bus.register("net" + this.id + "-send", function(data)
    {
        this.send(data);
    }, this);

    //Object.seal(this);
}

FetchNetworkAdapter.prototype.destroy = function()
{
};

FetchNetworkAdapter.prototype.fetch = async function(url, options)
{
    if(this.cors_proxy) url = this.cors_proxy + encodeURIComponent(url);

    try
    {
        const resp = await fetch(url, options);
        const ab = await resp.arrayBuffer();
        return [resp, ab];
    }
    catch(e)
    {
        console.warn("Fetch Failed: " + url + "\n" + e);
        let headers = new Headers();
        headers.set("Content-Type", "text/plain");
        return [
            {
                status: 502,
                statusText: "Fetch Error",
                headers: headers,
            },
            new TextEncoder().encode(`Fetch ${url} failed:\n\n${e.stack}`).buffer
        ];
    }
};

/**
 * @param {Uint8Array} data
 */
FetchNetworkAdapter.prototype.send = function(data)
{
    let packet = {};
    parse_eth(data, packet);

    if(packet.tcp) {
        let reply = {};
        reply.eth = { ethertype: ETHERTYPE_IPV4, src: this.router_mac, dest: packet.eth.src };
        reply.ipv4 = {
            proto: IPV4_PROTO_TCP,
            src: packet.ipv4.dest,
            dest: packet.ipv4.src
        };

        let tuple = [
            packet.ipv4.src.join("."),
            packet.tcp.sport,
            packet.ipv4.dest.join("."),
            packet.tcp.dport
        ].join(":");


        if(packet.tcp.syn && packet.tcp.dport === 80) {
            if(this.tcp_conn[tuple]) {
                dbg_log("SYN to already opened port", LOG_FETCH);
            }
            const tcp_conn = new TCPConnection();
            tcp_conn.state = TCP_STATE_SYN_RECEIVED;
            tcp_conn.net = this;
            tcp_conn.tuple = tuple;
            this.tcp_conn[tuple] = tcp_conn;

            tcp_conn.on_data = async (data) => {
                tcp_conn.read = tcp_conn.read || "";
                tcp_conn.read += new TextDecoder().decode(data);
                if(tcp_conn.read && tcp_conn.read.indexOf("\r\n\r\n") !== -1) {
                    let offset = tcp_conn.read.indexOf("\r\n\r\n");
                    let headers = tcp_conn.read.substring(0, offset).split(/\r\n/);
                    let data = tcp_conn.read.substring(offset + 4);
                    tcp_conn.read = "";

                    let first_line = headers[0].split(" ");
                    let target = new URL("http://host" + first_line[1]);
                    if(/^https?:/.test(first_line[1])) {
                        target = new URL(first_line[1]);
                    }
                    let req_headers = new Headers();
                    for(let i = 1; i < headers.length; ++i) {
                        let parts = headers[i].split(": ");
                        let key =  parts[0].toLowerCase();
                        let value = parts[1];
                        if( key === "host" ) target.host = value;
                        else if( key.length > 1 ) req_headers.set(parts[0], value);
                    }

                    dbg_log("HTTP Dispatch: " + target.href, LOG_FETCH);
                    tcp_conn.name = target.href;
                    let opts = {
                        method: first_line[0],
                        headers: req_headers,
                    };
                    if(["put", "post"].indexOf(opts.method.toLowerCase()) !== -1) {
                        opts.body = data;
                    }
                    const [resp, ab] = await tcp_conn.net.fetch(target.href, opts);
                    const lines = [
                        `HTTP/1.1 ${resp.status} ${resp.statusText}`,
                        "connection: Closed",
                        "content-length: " + ab.byteLength
                    ];

                    lines.push("x-was-fetch-redirected: " + String(resp.redirected));
                    lines.push("x-fetch-resp-url: " + String(resp.url));

                    resp.headers.forEach(function (value, key) {
                        if([
                            "content-encoding", "connection", "content-length", "transfer-encoding"
                        ].indexOf(key.toLowerCase()) === -1 ) {
                            lines.push(key + ": " + value);
                        }
                    });

                    lines.push("");
                    lines.push("");

                    tcp_conn.write(new TextEncoder().encode(lines.join("\r\n")));
                    tcp_conn.write(new Uint8Array(ab));
                }
            };

            tcp_conn.accept(packet);

            return;
        }

        if(!this.tcp_conn[tuple]) {
            dbg_log(`I dont know about ${tuple}, so restting`, LOG_FETCH);
            let bop = packet.tcp.ackn;
            if(packet.tcp.fin || packet.tcp.syn) bop += 1;
            reply.tcp = {
                sport: packet.tcp.dport,
                dport: packet.tcp.sport,
                seq: bop,
                ackn: packet.tcp.seq + (packet.tcp.syn ? 1: 0),
                winsize: packet.tcp.winsize,
                rst: true,
                ack: packet.tcp.syn
            };
            this.receive(make_packet(reply));
            return;
        }

        this.tcp_conn[tuple].process(packet);
    }

    if(packet.arp && packet.arp.oper === 1 && packet.arp.ptype === ETHERTYPE_IPV4) {
        arp_whohas(this, packet);
    }

    if(packet.dns) {
        let reply = {};
        reply.eth = { ethertype: ETHERTYPE_IPV4, src: this.router_mac, dest: packet.eth.src };
        reply.ipv4 = {
            proto: IPV4_PROTO_UDP,
            src: this.router_ip,
            dest: packet.ipv4.src,
        };
        reply.udp = { sport: 53, dport: packet.udp.sport };

        let answers = [];
        let flags = 0x8000; //Response,
        flags |= 0x0180; // Recursion
        // flags |= 0x0400; Authoritative

        for(let i = 0; i < packet.dns.questions.length; ++i) {
            let q = packet.dns.questions[i];

            switch(q.type){
                case 1: // A recrod
                    answers.push({
                        name: q.name,
                        type: q.type,
                        class: q.class,
                        ttl: 600,
                        data: [192, 168, 87, 1]
                    });
                    break;
                default:
            }
        }

        reply.dns = {
            id: packet.dns.id,
            flags: flags,
            questions: packet.dns.questions,
            answers: answers
        };
        this.receive(make_packet(reply));
        return;
    }

    if(packet.ntp) {
        ntp_response(this, packet);
        return;
    }

    // ICMP Ping
    if(packet.icmp && packet.icmp.type === 8) {
        icmp_echo(this, packet);
        return;
    }

    if(packet.dhcp) {
        dhcp_response(this, packet);
        return;
    }

    if(packet.udp && packet.udp.dport === 8) {
        udp_echo(this, packet);
    }
};

/**
 * @param {Uint8Array} data
 */
FetchNetworkAdapter.prototype.receive = function(data)
{
    this.bus.send("net" + this.id + "-receive", new Uint8Array(data));
};

if(typeof module !== "undefined" && typeof module.exports !== "undefined")
{
    module.exports["FetchNetworkAdapter"] = FetchNetworkAdapter;
}
