#include "getopt_win32.h"
#include <string.h>

char* optarg = NULL;
int optind = 1;
int optopt = 0;

int getopt(int argc, char* const argv[], const char* optstring) {
    static int current = 1;
    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;  // All arguments processed
    }

    char option = argv[optind][current++];
    const char* p = strchr(optstring, option);
    if (p == NULL) {
        optopt = option;
        return '?';  // Unknown option
    }

    if (*(p + 1) == ':') {
        if (argv[optind][current] != '\0') {
            optarg = &argv[optind][current];
            current = 1;
            optind++;
            return option;
        } else if (optind + 1 < argc && argv[optind + 1][0] != '-') {
            optarg = argv[optind + 1];
            current = 1;
            optind += 2;
            return option;
        } else {
            optarg = NULL;
            current = 1;
            optind++;
            return ':';
        }
    } else {
        if (argv[optind][current] == '\0') {
            current = 1;
            optind++;
        }
        return option;
    }
}

int getopt_long(int argc, char* const argv[], const char* optstring, const struct option* longopts, int* longindex) {
    static int current = 1;
    if (optind >= argc || argv[optind][0] != '-' || (argv[optind][1] == '-' && argv[optind][2] == '\0')) {
        return -1;  // All arguments processed
    }

    if (argv[optind][1] == '-') {
        const char* long_option = &argv[optind][2];
        const char* equals = strchr(long_option, '=');

        if (equals != NULL) {
            for (int i = 0; longopts[i].name != NULL; i++) {
                if (strncmp(long_option, longopts[i].name, equals - long_option) == 0) {
                    if (longopts[i].has_arg == required_argument) {
                        optarg = (char*)(equals + 1);
                        optind++;
                        if (longindex != NULL) {
                            *longindex = i;
                        }
                        return longopts[i].val;
                    }
                }
            }
            optopt = *long_option;
            return '?';  // Unknown option
        } else {
            for (int i = 0; longopts[i].name != NULL; i++) {
                if (strcmp(long_option, longopts[i].name) == 0) {
                    if (longopts[i].has_arg != no_argument) {
                        if (optind + 1 < argc && argv[optind + 1][0] != '-') {
                            optarg = argv[optind + 1];
                            optind += 2;
                            if (longindex != NULL) {
                                *longindex = i;
                            }
                            return longopts[i].val;
                        } else if (longopts[i].has_arg == required_argument) {
                            optarg = NULL;
                            optind++;
                            if (longindex != NULL) {
                                *longindex = i;
                            }
                            return ':';
                        }
                    } else {
                        optarg = NULL;
                        optind++;
                        if (longindex != NULL) {
                            *longindex = i;
                        }
                        return longopts[i].val;
                    }
                }
            }
            optopt = *long_option;
            return '?';  // Unknown option
        }
    } else {
        return getopt(argc, argv, optstring);
    }
}
