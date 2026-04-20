export interface Token {
  start: number;
  end: number;
  cssClass: string;
}

const TOP_KEYWORDS = new Set([
  "interface", "router", "bgp", "ospf", "ospfv3", "isis", "eigrp", "rip",
  "ip", "ipv6", "access-list", "crypto", "vlan", "vrf", "mpls", "aaa",
  "logging", "ntp", "snmp", "snmp-server", "telemetry", "segment-routing",
  "evpn", "l2vpn", "configure", "conf", "hostname", "no", "exit", "end",
  "write", "copy", "reload", "ping", "traceroute", "show", "debug", "do",
  "username", "enable", "disable", "service", "line", "class-map",
  "policy-map", "route-map", "spanning-tree", "tacacs", "tacacs-server",
  "radius", "radius-server", "ptp", "dhcp", "netconf", "version",
  "class", "policy", "prefix-set", "as-path-set", "community-set",
  "extcommunity-set", "flow", "track", "standby", "object-group",
  "banner", "cdp", "lldp", "vtp",
]);

const SUB_KEYWORDS = new Set([
  "description", "shutdown", "passive-interface", "bandwidth", "delay",
  "encapsulation", "switchport", "neighbor", "network", "redistribute",
  "route-target", "route-policy", "mtu", "duplex", "speed", "keepalive",
  "area", "metric", "distance", "address-family", "default-information",
  "summary-address", "timers", "authentication", "l2transport", "rewrite",
  "ingress", "egress", "tag", "push", "pop", "translate", "propagate",
  "cost", "priority", "weight", "local-preference", "community", "origin",
  "set", "match", "call", "continue", "drop", "pass", "prepend",
  "address", "next-hop", "local-as", "remove-private-as",
  "ip-address", "maximum-paths", "send-community", "soft-reconfiguration",
  "update-source", "ebgp-multihop", "remote-as", "password",
  // switchport
  "mode", "access", "trunk", "native", "nonegotiate", "violation",
  "restrict", "protect", "port-security", "mac-address", "aging", "sticky",
  // spanning-tree
  "portfast", "bpduguard",
  // ip sub-commands
  "verify", "source", "inspection", "snooping", "arp",
  "route", "helper-address", "directed-broadcast",
  // line sub-commands
  "synchronous", "login", "exec-timeout", "transport", "input", "output",
  // misc
  "privilege", "secret", "modulus", "general-keys", "motd", "ssh",
  "inactivity", "type", "maximum", "range", "algorithm-type", "run",
]);

const INTERFACE_NAMES =
  /^(GigabitEthernet|Gi|TenGigabitEthernet|Te|HundredGigabitEthernet|Hu|TwoHundredGigabitEthernet|FourHundredGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|FiftyGigabitEthernet|AppGigabitEthernet|FastEthernet|Fa|Bundle-Ether|BVI|GigE|Loopback|Lo|Tunnel|Tu|Vlan|Vl|Serial|Se|MgmtEth|Management|Mg|Port-channel|Po|Ethernet|Et|ATM|Dialer|Multilink|Cellular)([\/\d.:-]+)/i;

const PROMPT_RE = /^[A-Za-z0-9._-]+(?:\([A-Za-z0-9._\/-]+\))?[#>]\s*/;

const IPV4_RE = /\b(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?\b/;
const IPV6_RE = /\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(\/\d{1,3})?\b/;
const NUMBER_RE = /\b\d+(\.\d+)?\b/;
const WORD_RE = /[a-zA-Z0-9][-a-zA-Z0-9]*/;

export function tokenizeCiscoLine(line: string): Token[] {
  const tokens: Token[] = [];
  const trimmed = line.trimStart();

  if (trimmed === "") return tokens;

  if (trimmed.startsWith("!")) {
    tokens.push({ start: 0, end: line.length, cssClass: "chl-ios-comment" });
    return tokens;
  }

  const leadingWS = line.length - trimmed.length;
  let pos = leadingWS;

  // Detect IOS prompt: S1(config)# or Router>
  const promptMatch = trimmed.match(PROMPT_RE);
  if (promptMatch) {
    tokens.push({ start: pos, end: pos + promptMatch[0].length, cssClass: "chl-ios-prompt" });
    pos += promptMatch[0].length;
  }

  while (pos < line.length) {
    if (line[pos] === " " || line[pos] === "\t") {
      pos++;
      continue;
    }

    // Inline end-of-line comment
    if (line[pos] === "!" && (pos === 0 || line[pos - 1] === " " || line[pos - 1] === "\t")) {
      tokens.push({ start: pos, end: line.length, cssClass: "chl-ios-comment" });
      break;
    }

    // Skip markdown bold/italic markers so **keyword** still highlights correctly
    if (line[pos] === "*" || line[pos] === "_") {
      pos++;
      continue;
    }

    const slice = line.slice(pos);

    // Interface name (full and abbreviated)
    const ifaceMatch = slice.match(INTERFACE_NAMES);
    if (ifaceMatch && ifaceMatch.index === 0) {
      tokens.push({ start: pos, end: pos + ifaceMatch[0].length, cssClass: "chl-ios-type" });
      pos += ifaceMatch[0].length;
      continue;
    }

    // IPv6 before IPv4
    const ipv6Match = slice.match(IPV6_RE);
    if (ipv6Match && ipv6Match.index === 0) {
      tokens.push({ start: pos, end: pos + ipv6Match[0].length, cssClass: "chl-ios-number" });
      pos += ipv6Match[0].length;
      continue;
    }

    // IPv4
    const ipv4Match = slice.match(IPV4_RE);
    if (ipv4Match && ipv4Match.index === 0) {
      tokens.push({ start: pos, end: pos + ipv4Match[0].length, cssClass: "chl-ios-number" });
      pos += ipv4Match[0].length;
      continue;
    }

    // Word token
    const wordMatch = slice.match(WORD_RE);
    if (wordMatch && wordMatch.index === 0) {
      const word = wordMatch[0];
      const wordEnd = pos + word.length;

      if (word === "permit") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-permit" });
        pos = wordEnd;
        continue;
      }

      if (word === "deny") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-deny" });
        pos = wordEnd;
        continue;
      }

      if (word === "description") {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-builtin" });
        pos = wordEnd;
        if (pos < line.length) {
          tokens.push({ start: pos, end: line.length, cssClass: "chl-ios-string" });
          pos = line.length;
        }
        continue;
      }

      if (TOP_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-keyword" });
        pos = wordEnd;
        continue;
      }

      if (SUB_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ start: pos, end: wordEnd, cssClass: "chl-ios-builtin" });
        pos = wordEnd;
        continue;
      }

      pos = wordEnd;
      continue;
    }

    // Standalone number
    const numMatch = slice.match(NUMBER_RE);
    if (numMatch && numMatch.index === 0) {
      tokens.push({ start: pos, end: pos + numMatch[0].length, cssClass: "chl-ios-number" });
      pos += numMatch[0].length;
      continue;
    }

    pos++;
  }

  return tokens;
}
