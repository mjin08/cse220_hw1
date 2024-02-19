#include "hw1.h"

void print_packet_sf(unsigned char packet[])
{
    unsigned int source_address = (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | (packet[3] >> 4);
    unsigned int destination_address = ((packet[3] & 0x0f) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);
    unsigned int source_port = ((packet[7] >> 4) & 0xf);
    unsigned int destination_port = (packet[7] & 0xf);
    unsigned int fragment_offset = (packet[8] << 6) | (packet[9] >> 2);
    unsigned int packet_length = ((packet[9] << 12) & 0x02) | (packet[10] << 4) | (packet[11] >> 4);
    unsigned int maximum_hop_count = ((packet[11] & 0xf) << 1) | ((packet[12] >> 7) & 0x01);
    unsigned int checksum = ((packet[12]) & 0x7f) << 16 | (packet[13] << 8) | (packet[14]);
    unsigned int compression_scheme = (packet[15] >> 6); 
    unsigned int traffic_class = (packet[15] & 0x3f);
 
    printf("Source Address: %u\n", source_address);
    printf("Destination Address: %u\n", destination_address);
    printf("Source Port: %u\n", source_port);
    printf("Destination Port: %u\n", destination_port);
    printf("Fragment Offset: %u\n", fragment_offset);
    printf("Packet Length: %u\n", packet_length);
    printf("Maximum Hop Count: %u\n", maximum_hop_count);
    printf("Checksum: %u\n", checksum);
    printf("Compression Scheme: %u\n", compression_scheme);
    printf("Traffic Class: %u\n", traffic_class);
    printf("Payload:");

    for (int i = 0; i < packet_length - 16; i += 4) {
        unsigned int payload = (packet[16 + i] << 24) | (packet[16 + i + 1] << 16) | (packet[16 + i + 2] << 8) | packet[16 + i + 3];
        printf(" %d", payload);
    }
    printf("\n");
}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    unsigned int source_address = (packet[0] << 20) | (packet[1] << 12) | (packet[2] << 4) | (packet[3] >> 4);
    unsigned int destination_address = ((packet[3] & 0x0f) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);
    unsigned int source_port = ((packet[7] >> 4) & 0xf);
    unsigned int destination_port = (packet[7] & 0xf);
    unsigned int fragment_offset = (packet[8] << 6) | (packet[9] >> 2);
    unsigned int packet_length = ((packet[9] << 12) & 0x02) | (packet[10] << 4) | (packet[11] >> 4);
    unsigned int maximum_hop_count = ((packet[11] & 0xf) << 1) | ((packet[12] >> 7) & 0x01);
    unsigned int compression_scheme = (packet[15] >> 6); 
    unsigned int traffic_class = (packet[15] & 0x3f);
    
    unsigned int sum = 0; 
    sum = source_address + destination_address + source_port + destination_port + fragment_offset + packet_length + maximum_hop_count + compression_scheme + traffic_class;

    for (int i = 0; i < packet_length - 16; i += 4) {
        unsigned int payload = (packet[16 + i] << 24) | (packet[16 + i + 1] << 16) | (packet[16 + i + 2] << 8) | packet[16 + i + 3];
        sum += abs(payload);
    }

    return sum % ((1 << 23) - 1);
}


unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len)
{
    unsigned int num_ints = 0;

    for (unsigned int i = 0; i < packets_len; i++) {
        unsigned char *packet = packets[i];

        unsigned int checksum = ((packet[12]) & 0x7f) << 16 | (packet[13] << 8) | (packet[14]);
        unsigned int computed_sum = compute_checksum_sf(packets[i]);

        if (checksum == computed_sum) {
            unsigned int fragment_offset = ((packet[8] << 6) | (packet[9] >> 2)) / 4;
            unsigned int packet_length = ((packet[9] << 12) & 0x02) | (packet[10] << 4) | (packet[11] >> 4);
            
            for (int j = 0; j < packet_length - 16; j += 4) { 
                if (num_ints < array_len && fragment_offset < array_len) {
                    unsigned int payload = (packet[16 + j] << 24) | (packet[16 + j + 1] << 16) | (packet[16 + j + 2] << 8) | packet[16 + j + 3]; 
                    array[fragment_offset] = payload; 
                    fragment_offset++;
                    num_ints++;
                }
                else {
                    break;
                }
            }
        }
    }
    return num_ints;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    unsigned int num_packets = 0;

    for (unsigned int i = 0; i < array_len; i += max_payload / sizeof(int)) {
        unsigned char *packet = malloc(max_payload);
        packets[num_packets] = packet;

        unsigned int payload_length = max_payload - 16;
        
        int bytes_remaining = (array_len - i) * sizeof(int);
        if (bytes_remaining < payload_length) {
            payload_length = bytes_remaining;
        }

        unsigned int packet_length = payload_length + 16;
        unsigned int frag_offset = (i * sizeof(int)) / payload_length;
        unsigned int checksum = compute_checksum_sf(packet);

        packets[num_packets][0] = (src_addr >> 20) & 0xff;
        packets[num_packets][1] = (src_addr >> 12) & 0xff;
        packets[num_packets][2] = (src_addr >> 4) & 0xf;
        packets[num_packets][3] = ((src_addr & 0xf) << 4) | ((dest_addr >> 24) & 0xf);
        packets[num_packets][4] = (dest_addr >> 16) & 0xff;
        packets[num_packets][5] = (dest_addr >> 8) & 0xff;
        packets[num_packets][6] = dest_addr & 0xff;
        packets[num_packets][7] = (src_port << 4) | dest_port;
        packets[num_packets][8] = (frag_offset >> 6) & 0xff;
        packets[num_packets][9] = ((frag_offset & 0x3f) << 2) | ((packet_length >> 12) & 0x3);
        packets[num_packets][10] = (packet_length >> 4) & 0xff;
        packets[num_packets][11] = ((packet_length & 0xf) << 4) | ((maximum_hop_count >> 1) & 0xf);
        packets[num_packets][12] = ((maximum_hop_count & 0x1) << 7) | ((checksum >> 16) & 0x7f);
        packets[num_packets][13] = ((checksum >> 8) & 0xff);
        packets[num_packets][14] = (checksum & 0xff);
        packets[num_packets][15] = ((compression_scheme & 0x3) << 6) | (traffic_class & 0xff);

        for (int j = 0; j < payload_length; j++) {
            packets[num_packets][16 + j] = (unsigned char) array[i + j];
        }
        
        num_packets++;
        i += payload_length / sizeof(int);

        if (num_packets == packets_len || i >= array_len) {
            break;
        }
    }

    return num_packets;
}
