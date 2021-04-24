#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <string>
#include "decode.h"         // 嵌入到snort源码编译
struct pcap_file_info {
    FILE *fp = nullptr;
    time_t start_time = 0;
    uint32_t file_len = 0;
    uint32_t small_ip = 0;
    uint32_t big_ip = 0;
    std::string file_path;
};
static const int CHILD_NUM = 256;
struct pcap_save_node {
    pcap_file_info *info = nullptr;
    pcap_save_node *child[CHILD_NUM] = { 0 };
};
struct pcap_pkt_header {
    uint32_t time_sec = 0;
    uint32_t time_usec = 0;
    uint32_t cap_len = 0;
    uint32_t pkt_len = 0;
};
class pcap_save_tree {
public:
    pcap_save_tree() = default;
    virtual ~pcap_save_tree() {
        del_tree(root);
    }
    inline void set_save_dir(const char *path) {
        save_dir = path;
    }
    inline void set_file_limit(uint32_t size) {
        pcap_file_limit_size = size;
    }
    void save(const Packet *p) {
        if (!IS_IP4(p)) {       // 只处理ipv4
            return;
        }
        static const int ip_size = 2;
        static const int ip_number = 4; 
        static const char *pcap_header = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00";
        static const size_t pcap_header_len = 24;
        sfaddr_t *ip[ip_size] = { 0 };  // ip[0] -- small ip ip[1] -- big ip
        get_ip(p, ip[0], ip[1]);
        uint32_t index = 0;
        pcap_save_node *node = &root;
        for (int i = 0;i < ip_size;i++) {
            for (int j = 0;j < ip_number;j++) {
                index = ip[i]->ia8[12 + j];
                if (!node->child[index]) {
                    node->child[index] = new pcap_save_node;
                }
                node = node->child[index];
            }
        }
        if (!node->info) {
            node->info = new pcap_file_info;
        }
        if (!node->info->fp) {      // 首次打开文件
            node->info->start_time = time(0);
            get_file_path(ip, node);
            node->info->fp = fopen(node->info->file_path.c_str(), "wb+");
            if (!node->info->fp) {
                return;
            }
            fwrite(pcap_header, pcap_header_len, 1, node->info->fp);
            node->info->file_len = pcap_header_len;
            node->info->small_ip = ip[0]->ia32[3];
            node->info->big_ip = ip[1]->ia32[3];
        }
        pcap_pkt_header header;
        get_header(p, header);
        if (fwrite(&header, sizeof(header), 1, node->info->fp)) {
            node->info->file_len += sizeof(header);
            if (fwrite(p->pkt, header.cap_len, 1, node->info->fp)) {
                node->info->file_len += header.cap_len;
            }
            if (node->info->file_len >= pcap_file_limit_size) {
                fclose(node->info->fp);
                node->info->fp = nullptr;
            }
        }
    }
    inline void get_ip(const Packet *p, sfaddr_t *small_ip, sfaddr_t *big_ip) {
        sfaddr_t *sip = p->iph_api->iph_ret_src(p);
        sfaddr_t *dip = p->iph_api->iph_ret_dst(p);
        small_ip = sip;
        big_ip = dip;
        if (sip->ia32[3] > dip->ia32[3]) {
            small_ip = dip;
            big_ip = sip;
        }
    }
    inline void get_header(const Packet *p, pcap_pkt_header &header) {
        header.time_sec = p->pkth->ts.tv_sec;
        header.time_usec = p->pkth->ts.tv_usec;
        header.cap_len = p->pkth->caplen;
        header.pkt_len = p->pkth->ts.pktlen;
    }
    inline void get_file_path(const sfaddr_t **ip, pcap_save_node * node) {
        char buf[128] = "";
        snprintf(buf, sizeof(buf), "%s/%d.%d.%d.%d_%d.%d.%d.%d_%ld", 
                                    save_dir,
                                    ip[0]->ia8[12],
                                    ip[0]->ia8[13],
                                    ip[0]->ia8[14],
                                    ip[0]->ia8[15],
                                    ip[1]->ia8[12],
                                    ip[1]->ia8[13],
                                    ip[1]->ia8[14],
                                    ip[1]->ia8[15],
                                    node->info->start_time);
        node->info->file_path = buf;
    }
    void del_tree(pcap_save_node *&node) {
        if (!node) {
            return;
        }
        for (int i = 0;i < CHILD_NUM;i++) {
            if (node->child[i]) {
                del_tree(node->child[i]);
            }
        }
        if (node->info) {
            if (node->info->fp) {
                fclose(node->info->fp);
            }
            delete node->info;
        }
        if (node != &root) {
            delete node;
            node = nullptr;
        }
    }
private:
    const char *save_dir = "./";
    uint32_t pcap_file_limit_size = 1024 * 100;      // 100K
    pcap_save_node root;
};

