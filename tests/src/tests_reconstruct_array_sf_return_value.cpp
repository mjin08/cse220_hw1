#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "tests_aux.h"
extern "C" {
#include "hw1.h"
}

class reconstruct_array_sf_TestSuite : public testing::Test { };

TEST(reconstruct_array_sf_TestSuite, Test1_return_value)
{
	INFO("All packets have the same payload size. Target array is exactly the required size.");
    #include "reconstruct_array_sf_args01.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)expected_array;
    EXPECT_EQ(expected_num_elements, elements_written);
}

TEST(reconstruct_array_sf_TestSuite, Test2_return_value)
{
	INFO("All packets have the same payload size. Target array is smaller than the combined payloads of the packets.");
    #include "reconstruct_array_sf_args02.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)expected_array;
    EXPECT_EQ(expected_num_elements, elements_written);
}

TEST(reconstruct_array_sf_TestSuite, Test3_return_value)
{
	INFO("Last packet's payload is smaller than the rest. Target array is larger than the combined payloads of the packets.");
    #include "reconstruct_array_sf_args03.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)expected_array;
    EXPECT_EQ(expected_num_elements, elements_written);
}

TEST(reconstruct_array_sf_TestSuite, Test4_return_value)
{
	INFO("Last packet's payload is smaller than the rest. Some packets are corrupted.");
    #include "reconstruct_array_sf_args04.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)expected_array;
    EXPECT_EQ(expected_num_elements, elements_written);
}

TEST(reconstruct_array_sf_TestSuite, Test5_return_value)
{
	INFO("Several packets are corrupted.");
    #include "reconstruct_array_sf_args05.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)expected_array;
    EXPECT_EQ(expected_num_elements, elements_written);
}
