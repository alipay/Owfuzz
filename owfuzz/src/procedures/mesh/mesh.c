#include "mesh.h"
#include "../../fuzz_control.h"

#define MESH_STP "\x08\x02\x00\x00\x01\x80\xc2\x00\x00\x00\x04\xd9\xf5\x27\x32\x60\x04\xd9\xf5\x27\x32\x60\x10\x89\x42\x42\x03\x00\x00\x00\x00\x00\x80\x00\x04\xd9\xf5\x27\x32\x60\x00\x00\x00\x00\x80\x00\x04\xd9\xf5\x27\x32\x60\x80\x05\x00\x00\x14\x00\x02\x00\x02\x00"
#define MESH_STP_LEN 62

#define ASUS_PROBEREQ "\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\x04\xd9\xf5\x27\x32\x60\xff\xff\xff\xff\xff\xff\xb0\x6f\x00\x00\x01\x04\x02\x04\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x03\x01\x02\x2d\x1a\xef\x19\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x09\x05\x00\x08\x00\x00\x00\x00\xc0\x01\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x35\xf8\x32\xe4\x01\x01\x03\x04\x06\x04\xd9\xf5\x27\x32\x60\x05\x08\x52\x54\x2d\x41\x58\x39\x32\x55\x06\x08\x01\x04\xd9\xf5\x26\xff\xc0\xd3\x0f\x02\x00\x32\x10\x02\x00\xb4\x11\x02\x00\x3c\x16\x05\x43\x4e\x2f\x30\x31\xdd\x13\x00\x90\x4c\x04\x08\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x07\x00\x50\xf2\x08\x00\x12\x00\xdd\x09\x00\x10\x18\x02\x00\x00\x9c\x00\x00"
#define ASUS_PROBEREQ_1 "\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\x04\xd9\xf5\x27\x32\x70\xff\xff\xff\xff\xff\xff\xb0\x6f\x00\x00\x01\x04\x02\x04\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x03\x01\x02\x2d\x1a\xef\x19\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x09\x05\x00\x08\x00\x00\x00\x00\xc0\x01\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x35\xf8\x32\xe4\x01\x01\x03\x04\x06\x04\xd9\xf5\x27\x32\x70\x05\x08\x52\x54\x2d\x41\x58\x39\x32\x55\x06\x08\x01\x04\xd9\xf5\x26\xff\xc0\xd3\x0f\x02\x00\x32\x10\x02\x00\xb4\x11\x02\x00\x3c\x16\x05\x43\x4e\x2f\x30\x31\xdd\x13\x00\x90\x4c\x04\x08\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x07\x00\x50\xf2\x08\x00\x12\x00\xdd\x09\x00\x10\x18\x02\x00\x00\x9c\x00\x00"
#define ASUS_PROBEREQ_2 "\x40\x00\x00\x00\xff\xff\xff\xff\xff\xff\x04\xd9\xf5\x27\x32\x80\xff\xff\xff\xff\xff\xff\xb0\x6f\x00\x00\x01\x04\x02\x04\x0b\x16\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x03\x01\x02\x2d\x1a\xef\x19\x17\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\x09\x05\x00\x08\x00\x00\x00\x00\xc0\x01\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x35\xf8\x32\xe4\x01\x01\x03\x04\x06\x04\xd9\xf5\x27\x32\x80\x05\x08\x52\x54\x2d\x41\x58\x39\x32\x55\x06\x08\x01\x04\xd9\xf5\x26\xff\xc0\xd3\x0f\x02\x00\x32\x10\x02\x00\xb4\x11\x02\x00\x3c\x16\x05\x43\x4e\x2f\x30\x31\xdd\x13\x00\x90\x4c\x04\x08\xbf\x0c\xb2\x59\x81\x0f\xfa\xff\x00\x00\xfa\xff\x00\x00\xdd\x07\x00\x50\xf2\x08\x00\x12\x00\xdd\x09\x00\x10\x18\x02\x00\x00\x9c\x00\x00"

#define ASUS_PROBEREQ_LEN 194

#define LLDP_Multicast_addr "\x01\x80\xc2\x00\x00\x0e"

void find_mesh_node_by_beacon(struct packet *pkt)
{
    struct ieee_hdr *hdr = NULL;
    struct buf abuf = {0};
    uint8_t *tlvs = NULL;
    int tlvs_len = 0;
    uint8_t tlv_type = 0;
    uint8_t tlv_len = 0;
    uint8_t *tlv_value = NULL;
    int offset = 0;
    int nread = 0;
    uint8_t xssid[32] = {0};

    hdr = (struct ieee_hdr *)pkt->data;
    tlvs = pkt->data + sizeof(struct ieee_hdr) + sizeof(struct beacon_fixed);
    tlvs_len = pkt->len - sizeof(struct ieee_hdr) - sizeof(struct beacon_fixed);
    abuf.data = tlvs;
    abuf.len = tlvs_len;

    if (hdr->type != IEEE80211_TYPE_BEACON) {
        return;
    }

    offset = 0;
    while (tlvs_len > 0)
    {
        nread = read_tlv8(&abuf, offset, &tlv_type, &tlv_len, (const uint8_t **)&tlv_value);
        if (tlv_type == 0)
        {
            memset(xssid, 0, sizeof(xssid));
            memcpy(xssid, tlv_value, tlv_len);
        }

        if (tlv_type == 113 || tlv_type == 114 || tlv_type == 115 || tlv_type == 117 || tlv_type == 119)
        {
            fuzz_logger_log(FUZZ_LOG_INFO, "find mesh beacon [%s]", xssid);
        }

        offset += nread;
        tlvs_len -= nread;
    }
}

void find_mesh_node_by_lldp(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct ether_addr tmac, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;
    struct spanning_tree_protocol *stp;
    // struct packet stp_pkt = {0};
    struct packet probe_req = {0};

    hdr = (struct ieee_hdr *)pkt->data;
    if (hdr->type != IEEE80211_TYPE_DATA)
        return;

    stp = (struct spanning_tree_protocol *)(pkt->data + sizeof(struct ieee_hdr) + sizeof(struct llc_h));
    if (stp->identifier == 0 && stp->version_identifier == 0 && stp->bpdu_type == 0)
    {
        fuzz_logger_log(FUZZ_LOG_INFO, "find mesh stp root identifier [%02x:%02x:%02x:%02x:%02x:%02x]",
                        stp->root_bridge_system_id[0],
                        stp->root_bridge_system_id[1],
                        stp->root_bridge_system_id[2],
                        stp->root_bridge_system_id[3],
                        stp->root_bridge_system_id[4],
                        stp->root_bridge_system_id[5]);

        /*stp_pkt.channel = pkt->channel;
        stp_pkt.len = MESH_STP_LEN;
        memcpy(stp_pkt.data, MESH_STP, stp_pkt.len);
        send_packet_ex(&stp_pkt);*/
    }

    if (!memcmp(dmac.ether_addr_octet, LLDP_Multicast_addr, ETHER_ADDR_LEN))
    {
        fuzz_logger_log(FUZZ_LOG_INFO, "find ASUS mesh node [%02x:%02x:%02x:%02x:%02x:%02x]",
                        smac.ether_addr_octet[0],
                        smac.ether_addr_octet[1],
                        smac.ether_addr_octet[2],
                        smac.ether_addr_octet[3],
                        smac.ether_addr_octet[4],
                        smac.ether_addr_octet[5]);

        probe_req.channel = 1;
        probe_req.len = ASUS_PROBEREQ_LEN;
        memcpy(probe_req.data, ASUS_PROBEREQ, probe_req.len);
        send_packet_ex(&probe_req);

        /*probe_req.channel = 1;
        probe_req.len = ASUS_PROBEREQ_LEN;
        memcpy(probe_req.data, ASUS_PROBEREQ_1, probe_req.len);
        send_packet_ex(&probe_req);


        probe_req.channel = 1;
        probe_req.len = ASUS_PROBEREQ_LEN;
        memcpy(probe_req.data, ASUS_PROBEREQ_2, probe_req.len);
        send_packet_ex(&probe_req);*/
    }
}

void handle_mesh(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, struct ether_addr tmac, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;
    // struct packet mesh_stp = {0};

    hdr = (struct ieee_hdr *)pkt->data;

    switch (hdr->type)
    {
    case IEEE80211_TYPE_BEACON:
        find_mesh_node_by_beacon(pkt);
        break;
    case IEEE80211_TYPE_DATA:
        find_mesh_node_by_lldp(pkt, bssid, smac, dmac, tmac, fuzzing_opt);
        break;
    default:
        break;
    }
}
