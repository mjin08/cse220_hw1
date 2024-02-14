#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>
#include "gtest/gtest.h"

#define INFO(MSG) std::cerr << "[          ] [ INFO ] " << (MSG) << std::endl

void switch_stdout(const char *newStream);
void revert_stdout();
char *load_file(const char *filename);
void expect_no_valgrind_errors(int status);
int run_using_system(const char *test_name, const char *args);

void print_bytes(unsigned char bytes[], unsigned int array_len);
void verify_packets(char *expected_packets[], unsigned char *actual_packets[], 
    				unsigned int *expected_packet_lengths, unsigned int num_expected_packets);