#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "gtest/gtest.h"
#include "tests_aux.h"
extern "C" {
#include "hw1.h"
}

class print_packet_sf_TestSuite : public testing::Test {};

TEST(print_packet_sf_TestSuite, test1)
{
	unsigned char packet[] = {
		0x01,0xd2,0x08,0xa0,0xb4,0x11,0xaa,0xcd,0x00,0x00,0x01,0xca,0xde,0xad,0xb1,0xf3,0x00,0x84,0x5f,0xed,0xff,0xff,0x66,0x8f,0x05,0x88,0x81,0x92,
	};

	const char *expected_filename = "./tests/expected_outputs/print_packet_sf01.txt";
	char *expected_output = load_file(expected_filename);
	assert(expected_output != NULL);

	mkdir("./tests/actual_outputs/", 0700);
	const char *actual_filename = "./tests/actual_outputs/print_packet_sf01.txt";
	(void)remove(actual_filename);
	switch_stdout(actual_filename);
	print_packet_sf(packet);
	revert_stdout();

	char *actual_output = load_file(actual_filename);
	assert(actual_output != NULL);

	EXPECT_STREQ(expected_output, actual_output);
	free(expected_output);
	free(actual_output);
}

TEST(print_packet_sf_TestSuite, test2)
{
	unsigned char packet[] = {
		0x0e,0x4e,0x1c,0x00,0xd5,0x9f,0x80,0x87,0x54,0xe0,0x02,0x49,0x81,0x2a,0x25,0x1a,0x00,0x01,0x62,0xbc,0x00,0x0c,0xa2,0x4e,0xff,0xff,0xdc,0x5d,0x00,0x00,0x1d,0xd2,0x00,0x06,0xc8,0x1c,
	};

	const char *expected_filename = "./tests/expected_outputs/print_packet_sf02.txt";
	char *expected_output = load_file(expected_filename);


	const char *actual_filename = "./tests/actual_outputs/print_packet_sf02.txt";
	(void)remove(actual_filename);
	switch_stdout(actual_filename);
	print_packet_sf(packet);
	revert_stdout();

	char *actual_output = load_file(actual_filename);

	EXPECT_STREQ(expected_output, actual_output);
	free(expected_output);
	free(actual_output);
}

