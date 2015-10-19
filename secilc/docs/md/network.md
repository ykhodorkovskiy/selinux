Network Labeling Statements {#network_labeling}
===========================

ipaddr
------

Declares a named IP address in IPv4 or IPv6 format that may be
referenced by other CIL statements (i.e. `netifcon`).

Notes:

-   CIL statements utilising an IP address may reference a named IP
    address or use an anonymous address, the examples will show each
    option.

-   IP Addresses may be declared without a previous declaration by
    enclosing within parentheses e.g. `(127.0.0.1)` or `(::1)`.

**Statement definition:**

    (ipaddr ipaddr_id ip_address)

**Where:**

+--------------------+--------------------------------------------------------+
| `ipaddr`           | The `ipaddr` keyword.                                  |
+--------------------+--------------------------------------------------------+
| `ipaddr_id`        | The IP address identifier.                             |
+--------------------+--------------------------------------------------------+
| `ip_address`       | A correctly formatted IP address in IPv4 or IPv6       |
|                    | format.                                                |
+--------------------+--------------------------------------------------------+

**Example:**

This example declares a named IP address and also passes an 'explicit
anonymously declared' IP address to a macro:

    (ipaddr netmask_1 255.255.255.0)
    (context netlabel_1 (system.user object_r unconfined.object low_low)

    (call build_nodecon ((192.168.1.64) netmask_1))

    (macro build_nodecon ((ipaddr ARG1) (ipaddr ARG2))
        (nodecon ARG1 ARG2  netlabel_1))
          

netifcon
--------

Label network interface objects (e.g. `eth0`).

**Statement definition:**

    (netifcon netif_name netif_context_id packet_context_id)

**Where:**

+--------------------+--------------------------------------------------------+
| `netifcon`         | The `netifcon` keyword.                                |
+--------------------+--------------------------------------------------------+
| `netif_name`       | The network interface name (e.g. `wlan0`).             |
+--------------------+--------------------------------------------------------+
| `netif_context_id` | The security context to be allocated to the network    |
|                    | interface.                                             |
|                    |                                                        |
|                    | A previously declared `context` identifier or an       |
|                    | anonymous security context                             |
|                    | (`user role type levelrange`), the range MUST be       |
|                    | defined whether the policy is MLS/MCS enabled or not.  |
+--------------------+--------------------------------------------------------+
| `packet_context_id | The security context to be allocated to packets. Note  |
| `                  | that these are defined but currently unused as the     |
|                    | **`iptables`**`(8)` SECMARK services should be used to |
|                    | label packets.                                         |
|                    |                                                        |
|                    | A previously declared `context` identifier or an       |
|                    | anonymous security context                             |
|                    | (`user role type levelrange`), the range MUST be       |
|                    | defined whether the policy is MLS/MCS enabled or not.  |
+--------------------+--------------------------------------------------------+

**Examples:**

These examples show named and anonymous `netifcon` statements:

    (context context_1 (unconfined.user object_r unconfined.object low_low))
    (context context_2 (unconfined.user object_r unconfined.object (systemlow level_2)))

    (netifcon eth0 context_1 (unconfined.user object_r unconfined.object levelrange_1))
    (netifcon eth1 context_1 (unconfined.user object_r unconfined.object ((s0) level_1)))
    (netifcon eth3 context_1 context_2)
          

nodecon
-------

Label network address objects that represent IPv4 or IPv6 IP addresses
and network masks.

IP Addresses may be declared without a previous declaration by enclosing
within parentheses e.g. `(127.0.0.1)` or `(::1)`.

**Statement definition:**

    (nodecon subnet_id netmask_id context_id)

**Where:**

+--------------------+--------------------------------------------------------+
| `nodecon`          | The `nodecon` keyword.                                 |
+--------------------+--------------------------------------------------------+
| `subnet_id`        | A previously declared `ipaddr` identifier, or an       |
|                    | anonymous IPv4 or IPv6 formatted address.              |
+--------------------+--------------------------------------------------------+
| `netmask_id`       | A previously declared `ipaddr` identifier, or an       |
|                    | anonymous IPv4 or IPv6 formatted address.              |
+--------------------+--------------------------------------------------------+
| `context_id`       | A previously declared `context` identifier or an       |
|                    | anonymous security context                             |
|                    | (`user role type levelrange`), the range MUST be       |
|                    | defined whether the policy is MLS/MCS enabled or not.  |
+--------------------+--------------------------------------------------------+

**Examples:**

These examples show named and anonymous `nodecon` statements:

    (context context_1 (unconfined.user object_r unconfined.object low_low))
    (context context_2 (unconfined.user object_r unconfined.object (systemlow level_2)))

    (ipaddr netmask_1 255.255.255.0)
    (ipaddr ipv4_1 192.168.1.64)

    (nodecon netmask_1 ipv4_1 context_2)
    (nodecon (255.255.255.0) (192.168.1.64) context_1)
    (nodecon netmask_1 (192.168.1.64) (unconfined.user object_r unconfined.object ((s0) (s0 (c0)))))
             

portcon
-------

Label a udp or tcp port.

**Statement definition:**

    (portcon protocol port|(port_low port_high) context_id)

**Where:**

+--------------------+--------------------------------------------------------+
| `portcon`          | The `portcon` keyword.                                 |
+--------------------+--------------------------------------------------------+
| `protocol`         | The protocol keyword `tcp` or `udp`.                   |
+--------------------+--------------------------------------------------------+
| `port |`           | A single port to apply the context, or a range of      |
|                    | ports.                                                 |
| `(port_low port_hi |                                                        |
| gh)`               | The entries must consist of numerics `[0-9]`.          |
+--------------------+--------------------------------------------------------+
| `context_id`       | A previously declared `context` identifier or an       |
|                    | anonymous security context                             |
|                    | (`user role type levelrange`), the range MUST be       |
|                    | defined whether the policy is MLS/MCS enabled or not.  |
+--------------------+--------------------------------------------------------+

**Examples:**

These examples show named and anonymous `portcon` statements:

    (portcon tcp 1111 (unconfined.user object_r unconfined.object ((s0) (s0 (c0)))))
    (portcon tcp 2222 (unconfined.user object_r unconfined.object levelrange_2))
    (portcon tcp 3333 (unconfined.user object_r unconfined.object levelrange_1))
    (portcon udp 4444 (unconfined.user object_r unconfined.object ((s0) level_2)))
    (portcon tcp (2000 20000) (unconfined.user object_r unconfined.object (systemlow level_3)))
             
