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
            unsigned int fragment_offset = (packet[8] << 6) | (packet[9] >> 2);
            unsigned int packet_length = ((packet[9] << 12) & 0x02) | (packet[10] << 4) | (packet[11] >> 4);
            
            for (int i = 0; i < packet_length - 16; i += 4) { 
                if (num_ints < array_len) {
                    unsigned int payload = (packet[16 + i] << 24) | (packet[16 + i + 1] << 16) | (packet[16 + i + 2] << 8) | packet[16 + i + 3]; 
                    array[num_ints] = payload; 
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
    (void)array;
    (void)array_len;
    (void)packets;
    (void)packets_len;
    (void)max_payload;
    (void)src_addr;
    (void)dest_addr;
    (void)src_port;
    (void)dest_port;
    (void)maximum_hop_count;
    (void)compression_scheme;
    (void)traffic_class;
    return -1;
}
