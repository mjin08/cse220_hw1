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

    for (int i = 16; i < packet_length; i += 4) {
        unsigned int payload = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
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

    for (unsigned int i = 16; i < packet_length; i += 4) {
        int payload = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
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
            
            for (unsigned int j = 0; j < packet_length - 16; j += 4) { 
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
    unsigned int i = 0;
    unsigned int counter = 0;
    unsigned int frag_offset = 0;

    for (; i < packets_len && counter < array_len; i++) {

        unsigned int payload_length;
        if ((array_len - counter) > (max_payload / 4)) {
            payload_length = max_payload / 4;
        } else {
            payload_length = array_len - counter;
        }

        unsigned int num_bytes = (payload_length * 4);
        
        if (num_bytes < max_payload) {
            num_bytes = 16 + max_payload; 
        } else {
            num_bytes = 16 + (num_bytes * 4);
        }

        unsigned int num_payloads = max_payload / 4;
       
        unsigned int packet_length;
        if (array_len - (num_payloads * i) >= (payload_length)) {
            packet_length = max_payload + 16;
        } else {
            packet_length = 16 + (payload_length * 4);
        }
        
        // unsigned int frag_offset = (payload_length * 4 * i);

        packets[i] = malloc(num_bytes);

        packets[i][0] = (src_addr >> 20) & 0xff;
        packets[i][1] = (src_addr >> 12) & 0xff;
        packets[i][2] = (src_addr >> 4) & 0xff;
        packets[i][3] = ((src_addr & 0xf) << 4) | ((dest_addr >> 24) & 0xf);
        packets[i][4] = (dest_addr >> 16) & 0xff;
        packets[i][5] = (dest_addr >> 8) & 0xff;
        packets[i][6] = dest_addr & 0xff;
        packets[i][7] = (src_port << 4) | dest_port;
        packets[i][8] = (frag_offset >> 6) & 0xff;
        packets[i][9] = ((frag_offset & 0x3f) << 2) | ((packet_length >> 12) & 0x3);
        packets[i][10] = (packet_length >> 4) & 0xff;
        packets[i][11] = ((packet_length & 0xf) << 4) | ((maximum_hop_count >> 1) & 0xf);
        packets[i][12] = ((maximum_hop_count & 0x01) << 7); 
        // packets[i][12] = ((maximum_hop_count & 0x1) << 7) | ((checksum >> 16) & 0x7f);
        // packets[i][13] = ((checksum >> 8) & 0xff);
        // packets[i][14] = (checksum & 0xff);
        packets[i][15] = ((compression_scheme & 0x3) << 6) | (traffic_class & 0xff);

        int j = 16;
        for (unsigned int n = 0; n < num_payloads; n++) {
            packets[i][j] = (array[counter] >> 24);
            packets[i][j+1] = (array[counter] >> 16) & 0xff;
            packets[i][j+2] = (array[counter] >> 8) & 0xff;
            packets[i][j+3] = array[counter] & 0xff;
            counter++;
            j += 4;
        }
        frag_offset += max_payload;

        unsigned int checksum = compute_checksum_sf(packets[i]);
        packets[i][12] = ((maximum_hop_count & 0x01) << 7) | ((checksum >> 16) & 0x7f);
        packets[i][13] = ((checksum >> 8) & 0xff);
        packets[i][14] = (checksum & 0xff);
    }

    return i;
}
