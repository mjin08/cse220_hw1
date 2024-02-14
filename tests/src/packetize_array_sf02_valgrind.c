#include "hw1.h"

int  main() {
    #include "packetize_array_sf_args02.h"
	packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class);
	for (unsigned int i = 0; i < num_expected_packets; i++)
        free(actual_packets[i]);
    return 0;
}
