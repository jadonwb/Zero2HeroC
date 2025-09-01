#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "parse.h"

int list_employees(struct dbheader_t *dbhdr, struct employee_t *employees) {
  if (dbhdr == NULL) {
    printf("Invalid header pointer\n");
    return STATUS_ERROR;
  }

  if (employees == NULL) {
    printf("Invalid employees pointer\n");
    return STATUS_ERROR;
  }

  int i = 0;
  for (; i < dbhdr->count; i++) {
    printf("Employee %d:\n", i);
    printf("\tName: %s\n", employees[i].name);
    printf("\tAddress: %s\n", employees[i].address);
    printf("\tHours: %u\n", employees[i].hours);
  }

  return STATUS_SUCCESS;
}

int remove_employee(struct dbheader_t *dbhdr, struct employee_t **employees,
                    char *name) {
  if (dbhdr == NULL) {
    printf("Invalid header pointer\n");
    return STATUS_ERROR;
  }

  if (employees == NULL) {
    printf("Invalid employees pointer\n");
    return STATUS_ERROR;
  }

  int i = 0;
  for (; i < dbhdr->count; i++) {
    if (strncmp((*employees)[i].name, name, sizeof((*employees)[i].name)) ==
        0) {
      break;
    }
  }

  if (i == dbhdr->count) {
    printf("Employee not found\n");
    return STATUS_ERROR;
  }

  int j = i;
  for (; j < dbhdr->count - 1; j++) {
    (*employees)[j] = (*employees)[j + 1];
  }

  dbhdr->count--;

  *employees = realloc(*employees, dbhdr->count * sizeof(struct employee_t));
  if (*employees == NULL && dbhdr->count > 0) {
    printf("Realloc failed to shrink employee array\n");
    return STATUS_ERROR;
  }

  return STATUS_SUCCESS;
}

int add_employee(struct dbheader_t *dbhdr, struct employee_t **employees,
                 char *addstring) {

  if (dbhdr == NULL) {
    printf("Invalid header pointer\n");
    return STATUS_ERROR;
  }

  if (employees == NULL) {
    printf("Invalid employees pointer\n");
    return STATUS_ERROR;
  }

  char *name = strtok(addstring, ",");
  char *addr = strtok(NULL, ",");
  char *hours = strtok(NULL, ",");
  if (name == NULL || addr == NULL || hours == NULL) {
    printf("Invalid add string format\n");
    return STATUS_ERROR;
  }

  dbhdr->count++;

  *employees = realloc(*employees, dbhdr->count * sizeof(struct employee_t));
  if (*employees == NULL) {
    printf("Realloc failed to expand employee array\n");
    return STATUS_ERROR;
  }

  strncpy((*employees)[dbhdr->count - 1].name, name,
          sizeof((*employees)[dbhdr->count - 1].name));
  strncpy((*employees)[dbhdr->count - 1].address, addr,
          sizeof((*employees)[dbhdr->count - 1].address));
  int hours_int = atoi(hours);
  if (hours_int < 0) {
    printf("Invalid hours value\n");
    return STATUS_ERROR;
  }
  (*employees)[dbhdr->count - 1].hours = hours_int;

  return STATUS_SUCCESS;
}

int read_employees(int fd, struct dbheader_t *dbhdr,
                   struct employee_t **employeesOut) {
  if (fd < 0) {
    printf("Invalid file descriptor\n");
    return STATUS_ERROR;
  }

  int count = dbhdr->count;

  struct employee_t *employees = calloc(count, sizeof(struct employee_t));
  if (employees == NULL) {
    printf("Malloc failed to create employee array\n");
    return STATUS_ERROR;
  }

  read(fd, employees, count * sizeof(struct employee_t));

  int i = 0;
  for (; i < count; i++) {
    employees[i].hours = ntohl(employees[i].hours);
  }

  *employeesOut = employees;
  return STATUS_SUCCESS;
}

int output_file(int fd, struct dbheader_t *dbhdr,
                struct employee_t *employees) {
  if (fd < 0) {
    printf("Invalid file descriptor\n");
    return STATUS_ERROR;
  }

  int realcount = dbhdr->count;
  size_t new_filesize =
      sizeof(struct dbheader_t) + (realcount * sizeof(struct employee_t));

  dbhdr->magic = htonl(dbhdr->magic);
  dbhdr->filesize = htonl(new_filesize);
  dbhdr->count = htons(dbhdr->count);
  dbhdr->version = htons(dbhdr->version);

  lseek(fd, 0, SEEK_SET);

  write(fd, dbhdr, sizeof(struct dbheader_t));

  for (int i = 0; i < realcount; i++) {
    employees[i].hours = htonl(employees[i].hours);
    write(fd, &employees[i], sizeof(struct employee_t));
  }

  if (ftruncate(fd, new_filesize) == -1) {
    perror("Failed to truncate file");
    return STATUS_ERROR;
  }

  return STATUS_SUCCESS;
}

int validate_db_header(int fd, struct dbheader_t **headerOut) {
  if (fd < 0) {
    printf("Invalid file descriptor\n");
    return STATUS_ERROR;
  }

  struct dbheader_t *header = calloc(1, sizeof(struct dbheader_t));
  if (header == NULL) {
    printf("Malloc failed to create db header\n");
    return STATUS_ERROR;
  }

  if (read(fd, header, sizeof(struct dbheader_t)) !=
      sizeof(struct dbheader_t)) {
    perror("read");
    free(header);
    return STATUS_ERROR;
  }

  header->version = ntohs(header->version);
  header->count = ntohs(header->count);
  header->magic = ntohl(header->magic);
  header->filesize = ntohl(header->filesize);

  if (header->magic != HEADER_MAGIC) {
    printf("Improper header magic\n");
    free(header);
    return STATUS_ERROR;
  }

  if (header->version != 0x1) {
    printf("Improper header version\n");
    free(header);
    return STATUS_ERROR;
  }

  struct stat dbstat = {0};
  fstat(fd, &dbstat);
  if (header->filesize != dbstat.st_size) {
    printf("Corrupted database\n");
    free(header);
    return STATUS_ERROR;
  }

  *headerOut = header;
  return STATUS_SUCCESS;
}

int create_db_header(struct dbheader_t **headerOut) {
  if (headerOut == NULL) {
    printf("Invalid header output pointer\n");
    return STATUS_ERROR;
  }

  struct dbheader_t *header = calloc(1, sizeof(struct dbheader_t));
  if (header == NULL) {
    printf("Malloc failed to create db header\n");
    return STATUS_ERROR;
  }

  header->version = 0x1;
  header->count = 0;
  header->magic = HEADER_MAGIC;
  header->filesize = sizeof(struct dbheader_t);

  *headerOut = header;
  return STATUS_SUCCESS;
}
