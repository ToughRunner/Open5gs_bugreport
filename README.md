# Open5gs AMF DOS Vulnerability

Recently, we discovered a logic vulnerability that may cause Open5gs AMF to crash during a code audit of Open5gs Ver2.4.9. 
The specific causes of the vulnerability are as follows:

## Vulnerability description

When AMF is initialized, the default maximum number of GNB per AMF/MME is defined to 64.

> /lib/app/ogs-context.c
```c=
#define MAX_NUM_OF_UE               1024    /* Num of UE per AMF/MME */
#define MAX_NUM_OF_GNB              64      /* Num of gNB per AMF/MME */

    self.max.gnb = MAX_NUM_OF_GNB;
    self.max.ue = MAX_NUM_OF_UE;
```

Memory pool is initialized according to the maximum value defined before.

> /src/amf/context.c
```c=
    /* Allocate TWICE the pool to check if maximum number of gNBs is reached */
    ogs_pool_init(&amf_gnb_pool, ogs_app()->max.gnb*2);
```

The request should fail when the NR initiates an `NG_Setup_Request` request to the core network if the maximum value of `NG_Setup_Request` is exceeded

```c=
    if (maximum_number_of_gnbs_is_reached()) {
        ogs_warn("NG-Setup failure:");
        ogs_warn("    Maximum number of gNBs reached");
        group = NGAP_Cause_PR_misc;
        cause = NGAP_CauseMisc_control_processing_overload;

        ogs_assert(OGS_OK ==
            ngap_send_ng_setup_failure(gnb, group, cause));
        return;
    }
```

However, the moment SCTP connection successfully established, `amf_gnb_t` structure is allocated and added to the list before any check.

> /src/amf/ngap-sctp.c
```c=
static void lksctp_accept_handler(short when, ogs_socket_t fd, void *data)
{
    ogs_assert(data);
    ogs_assert(fd != INVALID_SOCKET);

    ngap_accept_handler(data);
}
void ngap_accept_handler(ogs_sock_t *sock)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_sock_t *new = NULL;
    ogs_assert(sock);
    new = ogs_sock_accept(sock);
    if (new) {
        ...

        ngap_event_push(AMF_EVT_NGAP_LO_ACCEPT,
                new, addr, NULL, 0, 0);
        ...
    } else {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "accept() failed");
    }
}
```
> /src/amf/amf-context.c
```c=
    case AMF_EVT_NGAP_LO_ACCEPT:
        sock = e->ngap.sock;
        ogs_assert(sock);
        addr = e->ngap.addr;
        ogs_assert(addr);

        ogs_info("gNB-N2 accepted[%s] in master_sm module",
            OGS_ADDR(addr, buf));

        gnb = amf_gnb_find_by_addr(addr);
        if (!gnb) {
            gnb = amf_gnb_add(sock, addr);
            ogs_assert(gnb);
        } else {
            ogs_warn("gNB context duplicated with IP-address [%s]!!!",
                    OGS_ADDR(addr, buf));
            ogs_sock_destroy(sock);
            ogs_free(addr);
            ogs_warn("N2 Socket Closed");
        }

        break;
```
Function `amf_gnb_find_by_addr` performs a detection and does not allow the same IP to initiate multiple gNB Contexts, the detection function searches through the hash value of the ogs_sockaddr_t structure, so SCTP connections initiated by different ports of the same IP will also bypass this detection restriction.

Function `amf_gnb_find_by_addr` performs a detection using the hash value of `ogs_sockaddr_t` structure, which includes port number, so new SCTP connections initialed by different ports from the same IP address will be treated as a new one. Therefore, the cost of this attack is very low.

```c=
amf_gnb_t *amf_gnb_find_by_addr(ogs_sockaddr_t *addr)
{
    ogs_assert(addr);
    return (amf_gnb_t *)ogs_hash_get(self.gnb_addr_hash,
            addr, sizeof(ogs_sockaddr_t));

    return NULL;
}
```

In result, when an attacker initiates multiple NG setup requests, AMF will crash.


## POC
![](https://raw.githubusercontent.com/ToughRunner/Open5gs_bugreport/main/poc0.png)


## Upadate

We have reported this vulnerability to the vendor through email at 03 Aug 2022, but didn't get a reply.

The vendor pushed a [commit](https://github.com/open5gs/open5gs/commit/700c71ef4ceb279cacdb51b111dc9c94885dce23) at 05 Aug 2022, renaming the variable names from `gnb` to `peer` which didn't fix this vulnerability.

We confirmed that the latest version(2.4.10) is still affected by this vulnerability.

![](https://raw.githubusercontent.com/ToughRunner/Open5gs_bugreport/main/poc1.png)

## Acknowledgment
Credit to @ToughRunner,@leonW7,@HenryzhaoH from Shanghai Jiao Tong University.
