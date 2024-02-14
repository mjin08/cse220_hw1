#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "gtest/gtest.h"
#include "tests_aux.h"
extern "C" {
#include "hw1.h"
}

class packetize_array_sf_TestSuite : public testing::Test { };

TEST(packetize_array_sf_TestSuite, Test1_return_value)
{
	INFO("Packetize a short array. packets[] is the optimal length. All packets have the same size.");
	#include "packetize_array_sf_args01.h"
	unsigned int num_actual_packets = packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class);
	EXPECT_EQ(num_expected_packets, num_actual_packets);
}

TEST(packetize_array_sf_TestSuite, Test2_return_value)
{
	INFO("Packetize a short array. packets[] is the optimal length. Last packet is smaller than the rest.");
	#include "packetize_array_sf_args02.h"
	unsigned int num_actual_packets = packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class);
	EXPECT_EQ(num_expected_packets, num_actual_packets);
}

TEST(packetize_array_sf_TestSuite, Test3_return_value)
{
	INFO("Packetize a long array. packets[] is not long enough.");
	#include "packetize_array_sf_args03.h"
	unsigned int num_actual_packets = packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class);
	EXPECT_EQ(num_expected_packets, num_actual_packets);
}

TEST(packetize_array_sf_TestSuite, Test4_return_value)
{
	INFO("Packetize a long array. packets[] is long enough.");
	#include "packetize_array_sf_args04.h"
	unsigned int num_actual_packets = packetize_array_sf(array, sizeof(array) / sizeof(array[0]), actual_packets,
			sizeof(actual_packets) / sizeof(actual_packets[0]), max_payload, src_addr, dest_addr, src_port, dest_port, 
			maximum_hop_count, compression_scheme, traffic_class);
	EXPECT_EQ(num_expected_packets, num_actual_packets);
}