#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "common.h"
#include "file.h"
#include "parse.h"

void print_usage(char *argv[]) {
  printf("Usage: %s -n -f <database file>\n", argv[0]);
  printf("\t -n  - create new database file\n");
  printf("\t -f  - (required) path to database file\n");
}

int main(int argc, char *argv[]) {
  char *filepath = NULL;
  char *addstring = NULL;
  char *removename = NULL;
  char *updatestring = NULL;
  bool newfile = false;
  bool list = false;
  int c;
  int dbfd = -1;
  struct dbheader_t *header = NULL;
  struct employee_t *employees = NULL;

  while ((c = getopt(argc, argv, "nf:a:lr:u:")) != -1) {
    switch (c) {
    case 'n':
      newfile = true;
      break;
    case 'f':
      filepath = optarg;
      break;
    case 'a':
      addstring = optarg;
      break;
    case 'r':
      removename = optarg;
      break;
    case 'u':
      updatestring = optarg;
      break;
    case 'l':
      list = true;
      break;
    case '?':
      printf("Unknown option -%c\n", c);
      break;
    default:
      return -1;
    }
  }

  if (filepath == NULL) {
    printf("Filepath is a required argument\n");
    print_usage(argv);
    return 0;
  }

  if (newfile) {
    dbfd = create_db_file(filepath);
    if (dbfd == STATUS_ERROR) {
      printf("Unable to create database file\n");
      return -1;
    }

    if (create_db_header(&header) == STATUS_ERROR) {
      printf("Failed to create database header\n");
      return -1;
    }
  } else {
    dbfd = open_db_file(filepath);
    if (dbfd == STATUS_ERROR) {
      printf("Unable to open database file\n");
      return -1;
    }

    if (validate_db_header(dbfd, &header) == STATUS_ERROR) {
      printf("Failed to validate database header\n");
      return -1;
    }
  }

  if (read_employees(dbfd, header, &employees) == STATUS_ERROR) {
    printf("Failed to read employees from database\n");
    return -1;
  }

  if (addstring) {
    if (add_employee(header, &employees, addstring) == STATUS_ERROR) {
      printf("Failed to add employee\n");
      return -1;
    }
  }

  if (removename) {
    if (remove_employee(header, &employees, removename) == STATUS_ERROR) {
      printf("Failed to remove employee\n");
      return -1;
    }
  }

  if (updatestring) {
    if (update_employee(header, &employees, updatestring) == STATUS_ERROR) {
      printf("Failed to update employee\n");
      return -1;
    }
  }

  if (list) {
    if (list_employees(header, employees) == STATUS_ERROR) {
      printf("Failed to list employees\n");
      return -1;
    }
  }

  output_file(dbfd, header, employees);
}
