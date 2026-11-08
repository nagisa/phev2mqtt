# PHEV Remote protocol (MY18)

A brief description of the protocol used. Determined by analysis and reverse
engineering, together the looking at the [phev-remote](https://github.com/phev-remote)
code.

## Network transport

The client device connects to the car using an SSID with a default format
of *REMOTExxxxxx* where *xxxxxx* is an arbitrary string.

The car assigns the client an IP address over DHCP, usually 192.168.8.47. The
car itself is 192.168.8.46.

The client communicates to the car's address over TCP port 8080. Within the
TCP connection, binary packets are used to exchange data.

## Packet format

Each packet has the following format:

```text
|  1 byte   | 1 byte   | 1 byte | n bytes ... |   1 byte     |
|   [Type]    [Length]    [Ack]       [Data]     [Checksum]  |
```

The fields are:

### Type

One byte.

The type of the packet. Most packet types have a corresponding response type.
See below for known types.

### Length

One byte

The length of the packet, less two. For example a packet that contains two
data bytes has a length field of 4.

### Ack

One byte

The acknowledgement field. Will be 0 for request packets, and 1 for packets
acknowledging a request type.

### Data

Variable length

The data payload for the packet. Depends on the command. The length of this
field is 4 less than the value in the *Length* field.

### Checksum

One byte

The checksum is a basic packet integrity check. To calculate its value, add
up of all the previous bytes in the packet. The least significant octet is
the checksum.

For example, given a packet of `f3040020`, the sum is 0x117, so the checksum
is `0x17`. Thus the entire packet is `f304002017`.

## Security and XOR encoding

Most packets on the wire are encoded with a simple XOR obfuscation algorithm.
Packets from the car will be encoded using a rolling code scheme, and packets
from the client to the car are expected to be encoded similarly.

The algorithm was reverse engineered by @zivillian in
[this issue](https://github.com/buxtronix/phev2mqtt/issues/16) which
contains more detailed notes.

1. Initial security key

Shortly after client connection (and at occasional times during the connection), the
car sends an initialisation packet of type `0x5e` or `0x4e`, depending on the year.
The payload of this packet is used to firstly derive a `security_key` which is a
single byte.

Using this security key, a `key_map` is generated containing 256 distinct byte
values. These byte values are used for the lifetime of the connection or until
another initialisation packet is received.

Two index values are initialised, starting at zero. We'll call these `s_num` and
`r_num` for the send (to car) and receive (from car) directions. The `key_map`
values at the indices represented by `s_num` and `r_num` are the actual encoding
keys, we will call `s_key` and `r_key`.

2. Packet encoding

After the security key map has been established, all further packets to the car
must be "encrypted" with the current `s_key`. Packets received from the car will
be "encrypted" with the current `r_key`, so must be "decrypted" before further decoding.

The "encryption" is done by simply XORing each byte in the packet with the current
corresponding key value, either `key_map[s_num]` or `key_map[r_num]`. Being XOR,
the "decryption" is done the same symmetrical way.

3. s_num and r_num value incrementing

The send and receive keys (i.e `s_key` and `r_key`) only change when certain
packets are sent/received. Otherwise they may be used for multiple packets.

When the car sends a packet of type `0x6f`, the `r_num` is incremented, hence
the new `r_key` will be `key_map[r_num]`. Note that this change is used for
packets *after* the `0x6f` packet.

When the client sends a packet of type `0xf6`, the `s_num` is incremented, hence
the new `s_key` will be `key_map[s_num]`. Note that this change is used for
packets *after* the `0xf6` packet.

`r_num` or `s_num` rollover back to zero if they increment from `0xff`.

## Packet types

Summary:

| Value | Name              | Direction     | Description                          |
|-------|-------------------|---------------|--------------------------------------|
|  0xf3 | Ping Request      | client -> car | Ping/Keepalive request               |
|  0x3f | Ping response     | car -> client | Ping / Keepalive response            |
|  0x6f | Register changed  | car -> client | Notify a register has been updated   |
|  0xf6 | Register update   | client -> car | Client register change ack/set       |
|  0x5e | Security init     | car -> client | Initialise security keys (MY18)      |
|  0xe5 | Security ack      | client -> car | Ack security keys (MY18)             |
|  0x4e | Security init     | car -> client | Initialise security keys (MY14)      |
|  0xe4 | Security ack      | client -> car | Ack security keys (MY14)             |
|  0x2f | Keepalive request | car -> client | Sent by car to check client presence |
|  0xf2 | Start             | client -> car | Client hello carrying its MAC (MY18) |
|  0xbb | Bad Xor?          | car -> client | Sent when XOR value is incorrect.    |
|  0xcc | Decode failure    | car -> client | How the car decoded a bad message.   |

Replies use the request type with its nibbles swapped (`0x6f` -> `0xf6`,
`0x2f` -> `0xf2`, `0x3f` -> `0xf3`). A plain acknowledgement has ack `1`, the
same register, and a single `0x00` data byte.

### Start (0xf2)

```text
[f2][0a][00][01][<mac>][00][<cksum>]
```

Sent by the client after connecting. `<mac>` is the 6-byte MAC address of the
client's Wi-Fi interface.

### Ping request (0xf3)

Format:

```text
[f3][04][00][<seq>][00][<cksum>]
```

Seems to be a keepalive sent to the car from the client. The initial XOR seems to be 00
until a 0x5e packet is received from the car. The `<seq>` increments up to 0x63 then
overflows back to 0x0.

### Ping response (0x3f)

Format:

```text
[3f][04][01][<seq>][00][<cksum>]
```

Response to a 0xf3 packet, sent from the car to the client. The `<seq>` matches the
request, though the XOR seems to be chosen by the car and future register update packets
match this XOR until another ping exchange.

### Register changed (0x6f)

Format:

```text
[6f][<len>][<ack>][<register>][<data>][<cksum>]
```

Used to notify the client that a setting register has changed on the car.

If `<ack>` is zero, then indicates a notification of a register value. If `<ack>`
is one, this is a response to a register setting change requested by the client.

The `<register>` is a one-byte value signifying the corresponding register number.

The `<data>` is variable length and dependent on the specific register.

Registers are described below.

### Register update/ack (0xf6)

```text
[f6][<len>][<ack>][<register>][<data>][<cksum>]
```

Used by the client to notify the car of either an ack of a received register update, or setting a new register value.

If `<ack>` is zero, indicates that a register value is to be changed. The `<register>` and `<value>` fields indicate the register and new value.

If `<ack>` is one, is a response to an update (above) received from the car. The `<register>` field is the register value being acked. The `<data>` field contains a single `0x0`  byte.

### Init security (0x5e)

```text
[5e][0c][00][<data>][<cksum>]
```

Sent by the car after around initial ping/keepalive exchanges.

The `<data>` contents are 12 bytes, used to initialise the XOR encryption key map (see above).

This packet is not XOR encrypted.

### Init ack (0xe5)

```text
[e5][04][01][0100][<cksum>]
```

Sent in response to a 0x5e packet. Always seems to be the same.

This packet is not XOR encrypted.

### Bad XOR (0xbb)

```text
[bb][06][01][<unknown>][<exp>]
```

Sent by the car if a received packet is encoded with the incorrect XOR value.

The meaning of the value in the `<unknown>` field is, well, unknown.

The `<exp>` field contains the XOR value which is expected. If the offending
packet is reset using this value for the Xor, then it will likely be accepted.

This can be a workaround given the current unknown algorithm for generating
XOR values.

### Rekey (0xe5 / 0x5e)

```text
[e5][04][00][01][00][<cksum>]
```

Sent unencrypted by the client to ask for a new key (`0xe4` for MY14). The car
acknowledges with an encrypted `[5e][04][01][01][00]`, followed by an
unencrypted 0x5e security init packet carrying the new key. Both sides then
start again from the first key of the new key map.

The car looks for the unencrypted start response type before decrypting, so
an encrypted packet whose first byte happens to be `0xe5` (e.g. a `0xf6` packet
under key `0x13`) is dropped without advancing the car's receive key. The
client rekeys instead of sending such a packet.

### Decode failure (0xcc)

```text
[cc][04][01][<type>][<key>][<cksum>]
```

Sent by the car just before a 0xbb packet, when it fails to decode a packet
from the client. The car advances its receive key after any packet it fails to
decode, and the `<exp>` value of the following 0xbb packet is the key it will
use next.

The `<key>` field contains the XOR value the car used to decode the packet,
and `<type>` contains the first (type) byte of the packet as decoded with
that value. For a `0xf6` packet encoded with XOR `x` that means
`<type> = 0xf6 ^ x ^ <key>`.

## Registers

Registers contain the bulk of information on the state of the vehicle.

### Read registers (car to client)

There seem to be two types of register layout (A/B).

| Register | Name                         | Length | Location  | Fields                        | Description                                                                                         |
|----------|------------------------------|--------|-----------|-------------------------------|-----------------------------------------------------------------------------------------------------|
|0x1       | ??                           | 2      | 0         | [1,1]                         | Sent alongside the connection handshake, e.g. `0102`                                                |
|0x2       | Battery warning              | 4      | 2         | [1,1,1,1]                     |                                                                                                     |
|0x3       | Flags                        | 3      | 6         | [1,1,1]                       | Bit flags, e.g. `011573`. Byte 1 bit 2 relates to client registration, byte 2 bit 4 to car settings |
|0x4       | Charge timer settings        | 20 / 1 | 10 / ??   | [3,1,3,1,3,1,3,1,3,1] / []    |                                                                                                     |
|0x5       | Climate timer settings       | 16 / 1 | 30 / 235  | [1,2,1,2,1,2,1,2,1,2,1] / [1] |                                                                                                     |
|0x6       | ??                           | 20 / 1 | 74 / 46   | [1,17,1,1] / [1]              | Similar to 0x15, with a different first byte, e.g. `00` VIN `0002`                                         |
|0x7       | Wi-Fi channel                | 1      | 237       | [1]                           |                                                                                                     |
|0x8       | ??                           | 1      | 234       | [1]                           |                                                                                                     |
|0x9       | ??                           | 1      | 49        | [1]                           |                                                                                                     |
|0xa       | ??                           | 1      | 50        | [1]                           |                                                                                                     |
|0xb       | ??                           | 1      | 238 / 236 | [1]                           | Wi-Fi / version related                                                                             |
|0xc       | Air-con related              | 1      | 51        | [1]                           | Changes `01` -> `04` when the charger is unplugged                                                  |
|0xd       | Air-con related              | 1      | 52        | [1]                           | Changes `01` -> `02` when the charger is unplugged                                                  |
|0xe       | Charge setting               | 1      | 53        | [1]                           |                                                                                                     |
|0xf       | ??                           | 1      | 54        | [1]                           | Not used by the official app, e.g. `00`                                                             |
|0x10      | AirCon State                 | 3 / 1  | 55        | [1,1,1] / [1]                 | Alert, acknowledged by writing 0x13                                                                 |
|0x11      | ??                           | 1      | 58        | [1]                           | Not used by the official app, e.g. `00`                                                             |
|0x12      | TimeSync                     | 7      | 59        | [7]                           |                                                                                                     |
|0x13      | Alert                        | 1      | 66        | [1]                           | Acknowledged by writing 0x07                                                                        |
|0x14      | Alert                        | 7      | 67        | [6,1]                         | Acknowledged by writing 0x08                                                                        |
|0x15      | VIN                          | 20     | 246 / 74  | [19,11] / [1,17,1,1]          |                                                                                                     |
|0x16      | Vehicle settings             | 8      | 95        | [8]                           | See below                                                                                           |
|0x17      | Charge timer state           | 1      | 103       | [1]                           |                                                                                                     |
|0x18      | ??                           | 4 / 16 | 276 / 104 | [1,1,2] / [5,3,5,3]           | Bytes 0-1 are state flags                                                                           |
|0x19      | Air-con settings             | 9      | 120       | [1,5,3]                       |                                                                                                     |
|0x1a      | Ignition status              | 5 / 2  | 129       | [1,1,1,1,1] / [1,1]           |                                                                                                     |
|0x1b      | Charge / time setting        | 1      | 134       | [1]                           | Answered by writing its first byte to 0x17                                                          |
|0x1c      | AirCon Mode                  | 1      | 136       | [1]                           |                                                                                                     |
|0x1d      | Battery Level / light status | 4      | 137       | [1,1,1,1]                     |                                                                                                     |
|0x1e      | Charge plug status           | 2      | 141       | [1,1]                         | Alert, acknowledged by writing 0x12                                                                 |
|0x1f      | Charge State                 | 3      | 143       | [1,2]                         |                                                                                                     |
|0x20      | Charge settings              | 10     | 146       | [2,2,2,2,2]                   |                                                                                                     |
|0x21      | ??                           | 1      | 156       | [1]                           |                                                                                                     |
|0x22      | Air-con schedule             | 6      | 157       | [2,2,2]                       |                                                                                                     |
|0x23      | Interior/Hazard Lights + AC? | 5      | 163       | [1,1,1,1,1]                   |                                                                                                     |
|0x24      | Door Lock Status             | 10     | 168       | [1,1,1,1,1,1,1,1,1,1]         |                                                                                                     |
|0x25      | ??                           | 3      | 178       | [1,1,1]                       | Not used by the official app, e.g. `0e00ff`                                                         |
|0x26      | Alert                        | 1      | 181       | [1]                           | Raised while 0x1a byte 0 is 1-6                                                                     |
|0x27      | Connection related           | 1      | 182       | [1]                           |                                                                                                     |
|0x28      | Wi-Fi SSID                   | 32     | 183       | [33]                          | ASCII, padded with `0xff`                                                                           |
|0x29      | ??                           | 3 / 2  | 216       | [1,1,1] / [1,1]               | Byte 1 is shown on the main screen, byte 2 is a charge setting                                      |
|0x2a      | Flag                         | 1      | 219       | [1]                           |                                                                                                     |
|0x2b      | Version information          | 10     | 220       | [10]                          | Same location as 0xc0                                                                               |
|0x2c      | Flag                         | 1      | 233       | [1]                           |                                                                                                     |
|0xc0      | ECU Version                  | 13     | 220       | [10,2,1]                      |                                                                                                     |

### 0x02 - Battery warning

### 0x0b - Parking light status

### 0x05 - Climate timer

16 bytes.

|Byte(s) | Description |
|--------|-------------|
| 0      | Unknown     |
| 1-3    | Timer 1     |
| 4-6    | Timer 2     |
| 7-9    | Timer 3     |
| 10-12  | Timer 4     |
| 13-15  | Timer 5     |

#### Timer 1..5

__must be converted from big endian to little endian__ to be useful

```text
0xa5f0afe -> 0xfef0a5
```

```text
0xfef0a5 = 11111110 11110000 10100101
           |     |     |  |       | |
         Bit23 Bit17   |  Bit9    | Bit0
                     Bit12       Bit2
```

| __Bits__ | Description                                 |
|----------|---------------------------------------------|
| 0-1      | Duration: 0=10min 1=20min 2=30min ?3=40min? |
| 2        | Sunday                                      |
| 3        | Monday                                      |
| 4        | Tuesday                                     |
| 5        | Wednesday                                   |
| 6        | Thursday                                    |
| 7        | Friday                                      |
| 8        | Saturday                                    |
| 9-11     | Minute: 0=0 1=10 2=20 3=30 4=40 5=50        |
| 12-16    | Hour: 0=0 1=1 2=2 ... 21=21 22=22 23=23     |
| 17       | on                                          |
| 18       | off                                         |
| 19-23    | Unknown (unused?)                           |

### 0x10 - Preconditioning status

3 bytes.

| Byte(s) | Description |
|----------|-------------|
| 0 | Preconditioning state [0 = off, 2 = on, 3 = cancelled by open door/low battery] |
| 1 | Unknown |
| 2 | Unknown |

02b00b = windscreen on/10min
026e09 = windscreen on/10min (on another vehicle)
030000 = after door openining
000000 = precondition not active/terminated normally (e.g. timer elapsed.)

### 0x12 - Car time sync

### 0x15 - Vin / registration state

Vin info and regstration status.

| Byte(s) | Description |
|--|--|
|0 | Unknown |
|1-18 | VIN (ascii) |
|19 | Number of registered clients |

### 0x16 - Vehicle settings

8 bytes, carrying up to three vehicle settings. The car sends the whole
settings table as a series of these at the start of a connection, and again
when the client writes `fe00` to register 0x0f. It does not send them
periodically.

```text
[flag][a0][b0][a1][b1][a2][b2][00]
```

The flag is `02` or `00`; its meaning is unknown. Each `[a][b]` pair is one
setting, an ID of 0 means the slot is unused:

| Field   | Bits                         | Description                                          |
|---------|------------------------------|------------------------------------------------------|
| ID      | `a & 0x3f`                   | Setting ID, 1-60                                     |
| Value   | `(a >> 6) \| (b & 1) << 2`   | Selected option, 0-6. 7 means the car lacks the setting |
| Allowed | `b >> 1`                     | Bitmask of the options the car accepts, bit n is option n |

For example `00c41e850e861e00` holds settings 0x04=3 (allowed 0-3), 0x05=2
(allowed 0-2) and 0x06=2 (allowed 0-3).

A setting is changed by writing `[id][value]` to register 0x0f, followed by
`00` to register 0x0e. The car confirms the change with a 0x16 update carrying
the new value.

Known settings and their options:

| ID   | Setting                                          | Options |
|------|--------------------------------------------------|---------|
| 0x01 | Operation in key position                        | 0=ignition on or accessory, 1=ignition on |
| 0x02 | Lane-change signals (flash three times with 1 touch) | 0=off, 1=on |
| 0x03 | Turn signal lights answerback                    | 0=lock once, unlock twice; 1=lock once, unlock off; 2=lock off, unlock twice; 3=lock twice, unlock once; 4=lock off, unlock once; 5=lock twice, unlock off; 6=off |
| 0x04 | Windshield wipers intermittent operation         | 0=fixed (4 s), 1=adjustable, 2=adjustable & speed sensitive, 3=adjustable & rain sensitive |
| 0x05 | Wipers linked to washer                          | 0=off, 1=on, 2=on with delayed finishing wipe |
| 0x06 | Rear wiper intermittent interval                 | 0=0 s, 1=4 s, 2=8 s, 3=16 s |
| 0x07 | Charging lid light auto cut-out                  | 0=off, 1=1 min, 2=3 min, 3=5 min, 4=10 min |
| 0x08 | Auto fold mirrors                                | 0=off, 1=open by vehicle speed, 2=by ignition and driver door, 3=by keyless entry lock/unlock, 4=by keyless operation lock/unlock |
| 0x09 | Auto light sensitivity                           | 0=early, 1=somewhat early, 2=normal, 3=somewhat late, 4=late |
| 0x0a | Auto light linked to wiper                       | 0=off, 1=on |
| 0x0b | Dome light duration after door is closed         | 0=0 s, 1=7.5 s, 2=15 s, 3=30 s, 4=1 min, 5=2 min, 6=3 min |
| 0x0c | Headlight auto-cutout                            | 0=off, others uncertain |
| 0x0d | Interior light auto-cutout time                  | 0=off, 1=3 min, 2=30 min, 3=60 min |
| 0x0e | Activation time for lane-change signals          | 0=short, 1=long |
| 0x0f | Comfort washer                                   | 0=off, 1=on |
| 0x10 | Automatic unlock                                 | 0=off, 1=when shifted to park, 2=same with windows unlocked, 3=when ignition turned to lock, 4=same with windows unlocked |
| 0x11 | Unlock operation                                 | 0=all doors, 1=driver's door only |
| 0x13 | Lock button pushes for dead lock                 | 0=2 times, 1=1 time |
| 0x14 | Horn answerback at keyless entry lock            | 0=off, 1=one push, 2=one push at daytime, 3=two pushes, 4=two pushes at daytime |
| 0x15 | Keyless operation answerback beeps               | 0=all off, 1=keyless operation, 2=keyless entry, 3=all on |
| 0x16 | Automatic relock after remote unlock             | 0=30 s, 1=1 min, 2=2 min, 3=3 min |
| 0x18 | Timer function after ignition off                | 0=0 s, 1=30 s, 2=3 min, 3=10 min |
| 0x1a | Multi mode keyless entry                         | 0=off, 1=power window & door mirror open/close, 2=power window open/close, 3=power window close & door mirror open/close, 4=door mirror open/close, 5=power window close |
| 0x1c | Duration of horn answerback                      | 0=short, 1=long |
| 0x1d | Rear wiper activated in reverse                  | 0=when rear wiper on, 1=when front or rear wiper on |
| 0x20 | Remote unlock inactivation after locking         | 0=off, 1=3 s, 2=5 s |
| 0x21 | Horn answerback at remote engine start           | 0=off, 1=on |
| 0x22 | Open operation after ignition off                | 0=on, 1=off |
| 0x23 | Power window prohibited by lock-switch           | 0=all doors, 1=driver's door only |
| 0x24 | Auto cut of ACC power                            | 0=off, 1=30 min, 2=60 min |
| 0x2a | Headlights on when exiting vehicle               | 0=off, 1=15 s, 2=30 s, 3=1 min, 4=3 min |
| 0x2b | Exterior lights on with remote unlock            | 0=off, 1=parking lights, 2=headlights |
| 0x32 | Recirculation control                            | 0=manual, 1=automatic |
| 0x33 | A/C switch control                               | 0=manual, 1=automatic |
| 0x35 | Eco mode                                         | 0=eco, 1=comfort |
| 0x36 | Foot / defroster airflow ratio                   | 0=normal, 1=more to foot, 2=more to defroster |
| 0x37 | Face / foot airflow ratio                        | 0=normal, 1=more to face, 2=more to foot |
| 0x38 | Automatic rear defrost at start                  | 0=off, 1=on |
| 0x39 | Start A/C or heater at door unlock               | 0=off, 1=on |
| 0x3a | Slight defroster airflow in foot mode            | 0=off, 1=on |
| 0x3c | Fast idle for higher heater performance when stopped | 0=off, 1=on |

IDs 0x12, 0x17, 0x19, 0x1b, 0x1e, 0x1f, 0x25-0x29, 0x2c-0x31, 0x34 and 0x3b
also appear but have no known name.

### 0x17 - Charge timer state

### 0x1a - Ignition status

Probably some other info, but at least ignition status is shown.

| Byte | Description |
|--|--|
| 0 | Ignition state. 0x0=off 0x3=acc 0x4=on |
| 1-4 | Unknown, currently only seen as 0x0 |

### 0x1c - Aircon mode

Single byte.

| Value | Description |
|--|--|
|0 | Unknown |
|1 | Cooling |
|2 | Heating |
|3 | Windscreen |

### 0x1d - Drive battery level / parking light status

```text
10000003
```

| Byte(s) | Description |
|--|--|
|0 | Drive battery level % |
|1 | Unknown |
|2 | Parking light status 0/1 |
|3 | Unknown |

### 0x1e - Charge plug status

0000 - Unplugged
0001 - Plugged in, not charging

### 0x1f - Charging status

| Byte(s) | Description |
|--|--|
|0 | Charge status [0=not charging 1=charging]|
| 1-2 | Charge time remaining |

### 0x23 - Interior/Hazard lights + Something AC?

Interior lights ON: `0000000201`
Interior lights OFF: `0000000202`
Hazard lights ON: `0000000102`
Hazard lights OFF: `0000000202`

AC timer sniff:

| Mode | Start | End | Register |
|---|---|---|---|
| heat | 0 | 10 | 0001000202 |
| windscreen | 0 | 10 |  0101000202  |

### 0x24 - Door / Lock status

```text
Byte 0
|
1000000000
         |
       Byte 9
```

Below shows what is represented by each byte. For door/boot/bonnet,
the value is 1 if open, else 0.

0 - Lock status [1=locked 2=unlocked]

3 - Drivers Door (side depends if LHD/RHD)

4 - Front Passenger Door (side depends if LHD/RHD)

5 - Read Right Door

6 - Rear Left Door

7 - Boot / Trunk

8 - Bonnet / Hood

9 - Headlight state

### 0xc0 - ECU Version string

A string with the software version of the ECU.

## Write registers (client to car)

| Register | Name                       | Description/values     |
|----------|----------------------------|------------------------|
| 0x5      | Sync time                  | See below              |
| 0x3      | ??                         | 0x1 / 0x2; sent by the air-con screens, and periodically with 0x2 |
| 0x6      | Request udpated state      | 0x3                    |
| 0x7      | Acknowledge 0x13 alert     | 0x1, see below         |
| 0x8      | Acknowledge 0x14 alert     | 0x1, see below         |
| 0xa      | Set head lights            | 0x1=on 0x2=off         |
| 0xb      | Set parking lights         | 0x1=on 0x2=off         |
| 0xe      | Save settings??            | Sent after 0xf command |
| 0xf      | Update settings            | `[id][value]`, see 0x16; `fe00` requests the current settings |
| 0x10     | Register Wifi client       | 0x1                    |
| 0x11     | Allow any connection       | 0x0=off 0x1=on         |
| 0x12     | Acknowledge 0x1e alert     | 0x1, see below         |
| 0x13     | Reset PreAC state          | 0x1, acknowledges the 0x10 alert |
| 0x14     | Set Wi-Fi SSID             | 32 bytes               |
| 0x15     | Unregister Wifi client     | 0x1                    |
| 0x1a     | Set climate timer          | See below              |
| 0x1b     | Set climate state          | See below              |
| 0x17     | Cancel charge timer        |                        |
| 0x18     | Wi-Fi connection setting   | 1 byte                 |
| 0x19     | Set charge timer schedule  |                        |
| 0x1a     | Set climate timer schedule |                        |
| 0x1c     | Set Wi-Fi channel          | Channel number         |
| 0x1d     | Set Wi-Fi password         | 32 bytes               |
| 0x1e     | Power supply               | 0x0, probably stops the power outlet |

### Alert acknowledgements

Some register notifications are alerts that the client acknowledges by
writing `0x1` to a matching register:

| Notification | Acknowledgement |
|--------------|-----------------|
| 0x10         | 0x13            |
| 0x13         | 0x07, sent right away |
| 0x14         | 0x08            |
| 0x1e         | 0x12            |

In addition, a client answers a `0x1b` notification by writing its first byte
to `0x17`.

### 0x05 - Sync Time

8 bytes.

| Byte(s) | Description   |
|----------|---------------|
|       0 | Year - 2000   |
|       1 | Month         |
|       2 | Day of month  |
|       3 | Hour          |
|       4 | Minute        |
|       5 | Second        |
|       6 | Day of week   |
|       7 | Device rooted |

### 0x10 - Register wifi client

This command is issued when the car is in registration mode. A new client that connects
to the car sends this command, then the car registers its mac address as a valid client.

### 0x15 - Unregister Wifi client

This command is issued in any mode (registration or otherwise). It removes the Wifi
registration for the client (based on the MAC address it sees for the TCP client).

### 0x1a - set climate timer

16 bytes.

|Byte(s) | Description |
|--------|-------------|
| 0-2    | Timer 1     |
| 3-5    | Timer 2     |
| 6-8    | Timer 3     |
| 9-11   | Timer 4     |
| 12-14  | Timer 5     |
| 15     | Unknown     |

The Encoding for Timer 1 to 5 is the same as for [reading](#timer-15)

### 0x1b - set climate state

```text
[02[state][duration][start]]
```

* Byte 0 - 02
* Byte 1 - climate state
  * 01 - cooling
  * 02 - heating
  * 03 - windscreen
* Byte 2 - Duration
  * 00 - 10 mins
  * 01 - 20 mins
  * 02 - 30 mins
* Byte 3 - Delay before start
  * 00 - 0 mins / now
  * 01 - 5 mins
  * 02 - 10 mins

## Notes

Things discovered sniffing the app...

```text
AC data sniff.

Windscreen for 10 mins:

INFO[0000] out  [a1] REGISTER SET  (reg 0x1b data 02030000)
INFO[0000] in   [a1] REGISTER NTFY (reg 0x10 data 02b00b)
INFO[0000] in   [55] REGISTER NTFY (reg 0x1a data 0001000000)
INFO[0000] in   [70] REGISTER NTFY (reg 0x1c data 03)

Heat in 5 mins for 10 mins:

INFO[0000] out  [70] REGISTER SET  (reg 0x1b data 02020001)
INFO[0000] in   [01] REGISTER NTFY (reg 0x1a data 0000000101)
INFO[0000] in   [86] REGISTER NTFY (reg 0x1c data 02)

Heat in 0 mins for 10 mins:

INFO[0000] out  [73] REGISTER SET  (reg 0x1b data 02020000)
INFO[0000] in   [73] REGISTER NTFY (reg 0x10 data 02b020)
INFO[0000] in   [22] REGISTER NTFY (reg 0x1a data 0001000000)
INFO[0000] in   [50] REGISTER NTFY (reg 0x1c data 02)

Heat in 0 mins for 20 mins
INFO[0000] out  [4e] REGISTER SET  (reg 0x1b data 02020100)
INFO[0000] in   [1c] REGISTER NTFY (reg 0x10 data 02b034)
INFO[0000] in   [e7] REGISTER NTFY (reg 0x1a data 0001010000)
INFO[0000] in   [c6] REGISTER NTFY (reg 0x1c data 02)

Cool 0 mins for 10 mins
INFO[0170] out  [5f] REGISTER SET  (reg 0x1b data 02010000)
INFO[0170] in   [5b] REGISTER NTFY (reg 0x10 data 02b139)
INFO[0171] in   [18] REGISTER NTFY (reg 0x1a data 0001000000)
INFO[0171] in   [95] REGISTER NTFY (reg 0x1c data 01)

Cool 10 mins for 10 mins
SETREG 0x1b: -> 02010002

Climate timer:
t1 12:00 cool for 10 mins repeat sun:
set 0x1a: -> 04c00200fe0700fe0700fe0700fe0701
get 0x05: -> 0100fe0700fe0700fe0700fe0700fe07

t2 07:50 cool for 20 mins repeat sunMonTue:
set 0x1a: -> 04c0021d7a0200fe0700fe0700fe0701
get 0x05: -> 0204c00200fe0700fe0700fe0700fe07

disable all:

set 0x1a: 04c0041d7a0400fe0700fe0700fe0701

reset all:

set 0x1a: 00fe0700fe0700fe0700fe0700fe0701

Unplug charger (disabled due timer):

UPDATEREG 0x0c: 01 -> 04
UPDATEREG 0x0d: 01 -> 02
UPDATEREG 0x1e: 0001 -> 0000

Plug in charger (disabled due timer):

UPDATEREG 0x0d: 02 -> 01
UPDATEREG 0x1e: 0000 -> 0001

Plug in charger (within time period):
phev/register/1e 0002
charge starts:
phev/register/1e 0202

unplug:
phev/register/1e 0002
then:
phev/register/1e 0003

plug in:
phev/register/1e 0002
(charges)

unplug from charging:

UPDATEREG 0x1e: 0202 -> 0102
UPDATEREG 0x1e: 0102 -> 0002
UPDATEREG 0x1e: 0002 -> 0003

plug in, charge:

UPDATEREG 0x1e: 0000 -> 0002
UPDATEREG 0x1e: 0002 -> 0202

Charge timer:

disabl timer3: 0x19: 7d38b00183bd00017c70380200ffff0300ffff0302
enable timer3: 0x19: 7d38b00183bd00017c70380100ffff0300ffff0302

settings at 0x4

setting "exterior lights on rmt unlock:

- off -> 0x0f=2b00
- parking -> 0x0f=2b01
- head -> 0x0f=2b02

setting "charge light cutout"

- off  -> 0x0f=0700
- 1min -> 0x0f=0701
- 2min -> 0x0f=0702
- 5min -> 0x0f=0703
- 10min -> 0x0f=0704

setting "headlights on exiting vehicle"

- off -> 0x0f=2a00
- 15s -> 0x0f=2a01
- 30s -> 0x0f=2a02
- 1min-> 0x0f=2a03
- 3min-> 0x0f=2a04

light ones above followed by setting 0x0e->0x0
```
