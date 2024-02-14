#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "gtest/gtest.h"
#include "tests_aux.h"
extern "C" {
#include "hw1.h"
}

class packetize_array_sf_TestSuite : public testing::Test { };

TEST(packetize_array_sf_TestSuite, Test1_valgrind) {
	expect_no_valgrind_errors(run_using_system("packetize_array_sf01_valgrind", ""));	
}

TEST(packetize_array_sf_TestSuite, Test2_valgrind) {
	expect_no_valgrind_errors(run_using_system("packetize_array_sf02_valgrind", ""));
}

TEST(packetize_array_sf_TestSuite, Test3_valgrind) {
	expect_no_valgrind_errors(run_using_system("packetize_array_sf03_valgrind", ""));
}

TEST(packetize_array_sf_TestSuite, Test4_valgrind) {
	expect_no_valgrind_errors(run_using_system("packetize_array_sf04_valgrind", ""));
}