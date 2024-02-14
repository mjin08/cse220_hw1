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

TEST(reconstruct_array_sf_TestSuite, Test1_contents)
{
	INFO("All packets have the same payload size. Target array is exactly the required size.");
    #include "reconstruct_array_sf_args01.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)elements_written;
    (void)expected_num_elements;
    EXPECT_THAT(reconstructed_array, ::testing::ElementsAreArray(expected_array));
}

TEST(reconstruct_array_sf_TestSuite, Test2_contents)
{
	INFO("All packets have the same payload size. Target array is smaller than the combined payloads of the packets.");
    #include "reconstruct_array_sf_args02.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)elements_written;
    (void)expected_num_elements;
    EXPECT_THAT(reconstructed_array, ::testing::ElementsAreArray(expected_array));
}

TEST(reconstruct_array_sf_TestSuite, Test3_contents)
{
	INFO("Last packet's payload is smaller than the rest. Target array is larger than the combined payloads of the packets.");
    #include "reconstruct_array_sf_args03.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)elements_written;
    (void)expected_num_elements;
    EXPECT_THAT(reconstructed_array, ::testing::ElementsAreArray(expected_array));
}

TEST(reconstruct_array_sf_TestSuite, Test4_contents)
{
	INFO("Last packet's payload is smaller than the rest. Some packets are corrupted.");
    #include "reconstruct_array_sf_args04.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)elements_written;
    (void)expected_num_elements;
    EXPECT_THAT(reconstructed_array, ::testing::ElementsAreArray(expected_array));
}

TEST(reconstruct_array_sf_TestSuite, Test5_contents)
{
	INFO("Several packets are corrupted.");
    #include "reconstruct_array_sf_args05.h"
    unsigned int elements_written = reconstruct_array_sf((unsigned char **)packets, sizeof(packets)/sizeof(packets[0]), 
        reconstructed_array, sizeof(reconstructed_array) / sizeof(reconstructed_array[0]));
    (void)elements_written;
    (void)expected_num_elements;
    EXPECT_THAT(reconstructed_array, ::testing::ElementsAreArray(expected_array));
}
