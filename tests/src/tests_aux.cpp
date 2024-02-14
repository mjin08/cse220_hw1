#include "tests_aux.h"

static int fdesc;
static fpos_t pos;

void switch_stdout(const char *newStream) {
	(void)fflush(stdout);
	(void)fgetpos(stdout, &pos);
	fdesc = dup(fileno(stdout));
	(void)freopen(newStream, "w", stdout);
}

void revert_stdout() {
	(void)fflush(stdout);
	dup2(fdesc, fileno(stdout));
	close(fdesc);
	clearerr(stdout);
	(void)fsetpos(stdout, &pos);
}

char *load_file(const char *filename) {
	char *buffer = 0;
	long length;
	FILE *file = fopen(filename, "r");
	assert(file != NULL);
	(void)fseek(file, 0, SEEK_END);
	length = ftell(file);
	(void)fseek(file, 0, SEEK_SET);
	buffer = (char *)malloc(length + 1);
	if (buffer != NULL) {
		(void)fread(buffer, 1, length, file);
		(void)fclose(file);
		buffer[length] = '\0';
	}
	return buffer;
}

void expect_no_valgrind_errors(int status) {
    EXPECT_NE(37, WEXITSTATUS(status));
}

int run_using_system(const char *test_name, const char *args) {
    char executable[100];
    (void)sprintf(executable, "./build/%s", test_name);
    assert(access(executable, F_OK) == 0);
    char cmd[500];
    (void)sprintf(cmd, "ulimit -f 300; ulimit -t 4; valgrind --quiet -s --leak-check=full --show-leak-kinds=all --track-origins=yes --trace-children=yes --error-exitcode=37 %s %s",
	    executable, args);
	return system(cmd);
}

void print_bytes(unsigned char bytes[], unsigned int array_len) {
    for (unsigned int i = 0; i < array_len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void verify_packets(char *expected_packets[], unsigned char *actual_packets[], 
    				unsigned int *expected_packet_lengths, unsigned int num_expected_packets) {
	for (unsigned int i = 0; i < num_expected_packets; i++) {
		if (actual_packets[i] == NULL) {
			fprintf(stderr, "Packet #%u is NULL.\n", i);
			FAIL();
		}
		if (memcmp(expected_packets[i], actual_packets[i], expected_packet_lengths[i]) != 0) {
            printf("Contents of packet #%u incorrect.\n", i);
			printf("Expected:\n");
            print_bytes((unsigned char *)(expected_packets[i]), expected_packet_lengths[i]);
            printf("Actual:\n");
            print_bytes(actual_packets[i], expected_packet_lengths[i]);
        }
		EXPECT_EQ(memcmp(expected_packets[i], actual_packets[i], expected_packet_lengths[i]), 0);
    }
}