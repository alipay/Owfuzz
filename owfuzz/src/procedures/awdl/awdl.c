#include "awdl.h"
#include "../../fuzz_control.h"
#include "awdl_frame.h"
#include "wire.h"

// awdl data frame
/*
802.11hdr
llc_hdr
awdl_data_hdr
*/

// sizeof llc_hdr is 2 * sizeof(uint8_t) + 3 * sizeof(uint8_t) + sizeof(uint16_t) = 2 * 1 + 3 * 1 + 2 = 7
struct llc_hdr awdl_data_llc = {0xaa, 0xaa, 0x03, {0x00, 0x17, 0xf2}, 0x0800};
/*Seq num*/

// sizeof awdl_data is 4 * sizeof(uint16_t) = 2bytes => 8bytes
struct awdl_data awdl_data_hdr = {0x0304, 0x0000, 0x0000, 0x86dd};

int is_awdl_frame(struct packet *pkt)
{
    struct ieee_hdr *hdr;
    struct awdl_action *aa;

    hdr = (struct ieee_hdr *)pkt->data;
    if (hdr->type == IEEE80211_TYPE_ACTION)
    {
        aa = (struct awdl_action *)(pkt->data + sizeof(struct ieee_hdr));
        if (aa->category == IEEE80211_VENDOR_SPECIFIC)
        {
            if (0 == memcmp(&aa->oui, &AWDL_OUI, 3) && aa->type == AWDL_TYPE)
            {
                if (aa->subtype == AWDL_ACTION_PSF || aa->subtype == AWDL_ACTION_MIF)
                {
                    return 1;
                }
            }
        }
    }

    return 0;
}

void handle_awdl(struct packet *pkt, struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
    // struct ieee_hdr *hdr;
    struct awdl_action *aa;
    struct buf abuf = {0};
    uint8_t *tlvs;
    int tlvs_len;
    uint8_t tlv_type;
    uint16_t tlv_len;
    uint8_t *tlv_value;
    int offset;
    int nread;
    struct packet awdl_packet = {0};

    // hdr = (struct ieee_hdr *) pkt->data;
    aa = (struct awdl_action *)(pkt->data + sizeof(struct ieee_hdr));
    tlvs = pkt->data + sizeof(struct ieee_hdr) + sizeof(struct awdl_action);
    tlvs_len = pkt->len - sizeof(struct ieee_hdr) - sizeof(struct awdl_action);
    abuf.data = tlvs;
    abuf.len = tlvs_len;

    fuzz_logger_log(FUZZ_LOG_DEBUG, "Channel [%d] Action awdl -> [%02X:%02X:%02X:%02X:%02X:%02X] to [%02X:%02X:%02X:%02X:%02X:%02X] %s", pkt->channel,
                    smac.ether_addr_octet[0], smac.ether_addr_octet[1], smac.ether_addr_octet[2], smac.ether_addr_octet[3], smac.ether_addr_octet[4], smac.ether_addr_octet[5],
                    dmac.ether_addr_octet[0], dmac.ether_addr_octet[1], dmac.ether_addr_octet[2], dmac.ether_addr_octet[3], dmac.ether_addr_octet[4], dmac.ether_addr_octet[5],
                    awdl_frame_as_str(aa->subtype));

    offset = 0;
    while (tlvs_len)
    {
        nread = read_tlv(&abuf, offset, &tlv_type, &tlv_len, (const unsigned char **)&tlv_value);
        fuzz_logger_log(FUZZ_LOG_DEBUG, "tag: %s", awdl_tlv_as_str(tlv_type));

        offset += nread;
        tlvs_len -= nread;
    }

    if (aa->subtype == AWDL_ACTION_PSF)
    {
    }
    else if (aa->subtype == AWDL_ACTION_MIF)
    {
    }

    awdl_packet = create_action_awdl(SE_AWDLMAC, fuzzing_opt->target_addr, SE_BROADCASTMAC, pkt);
    send_packet_ex(&awdl_packet);

    fuzz_logger_log(FUZZ_LOG_DEBUG, "sending pkt len: %d", awdl_packet.len);
}