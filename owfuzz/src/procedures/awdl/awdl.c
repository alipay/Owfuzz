#include "awdl.h"

#include "awdl_frame.h"
#include "wire.h"

// awdl data frame
/*
802.11hdr
llc_hdr
awdl_data_hdr
*/
struct llc_hdr awdl_data_llc = {0xaa, 0xaa, 0x03, 0x00, 0x17, 0xf2, 0x08, 0x00};
                                              /*Seq num*/
struct awdl_data awdl_data_hdr = {0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x86, 0xdd};


int is_awdl_frame(struct packet *pkt)
{
    struct ieee_hdr *hdr;
    struct awdl_action *aa;

    hdr = (struct ieee_hdr *) pkt->data;
    if(hdr->type == IEEE80211_TYPE_ACTION)
    {
        aa = (struct awdl_action *)(pkt->data + sizeof(struct ieee_hdr));
        if(aa->category == IEEE80211_VENDOR_SPECIFIC)
        {
            if(0 == memcmp(&aa->oui, &AWDL_OUI, 3) && aa->type == AWDL_TYPE)
            {
                if(aa->subtype == AWDL_ACTION_PSF || aa->subtype == AWDL_ACTION_MIF)
                {
                    return 1;
                }
            }
        }

    }

    return 0;
}

void handle_awdl(struct packet *pkt,struct ether_addr bssid, struct ether_addr smac, struct ether_addr dmac, fuzzing_option *fuzzing_opt)
{
    struct ieee_hdr *hdr;
    struct awdl_action *aa;
    //struct buf fbuf;

    hdr = (struct ieee_hdr *) pkt->data;
    aa = (struct awdl_action *)(pkt->data + sizeof(struct ieee_hdr));

    if(aa->subtype == AWDL_ACTION_PSF)
    {

    }
    else if(aa->subtype == AWDL_ACTION_MIF)
    {

    }

    fuzz_logger_log("Action awdl -> %s", awdl_frame_as_str(aa->subtype));



}